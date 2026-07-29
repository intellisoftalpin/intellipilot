//! Local IP geolocation (V018).
//!
//! Every lookup is a local read against a MaxMind-format database on disk. The
//! only outbound request this module ever makes is fetching the database file
//! itself — no per-address service is ever contacted, so enabling the feature
//! does not leak user addresses to a third party.
//!
//! Off by default. Resolution is local, but the data it derives is personal,
//! so a superadmin opts in explicitly (`platform_settings.geoip_enabled`) and
//! can purge what was collected.
//!
//! Source is DB-IP Lite, published monthly, no account or licence key
//! required. It is CC BY 4.0, so the operator's instance downloads it and the
//! UI carries the required attribution; we never redistribute it. An operator
//! who already has a GeoLite2 file can upload it instead — same format.

use std::fmt;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use maxminddb::{Reader, geoip2};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

/// Where the monthly DB-IP Lite files are published.
pub const DEFAULT_BASE_URL: &str = "https://download.db-ip.com/free";

/// Cap on the decompressed database, a guard against a hostile or corrupt
/// response inflating until we run out of memory. The city variant is ~120 MB
/// decompressed, so this leaves generous headroom without being unbounded.
const MAX_DB_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum GeoIpError {
    #[error("database error: {0}")]
    Database(#[from] maxminddb::MaxMindDbError),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("download failed: {0}")]
    Download(String),
    #[error("no database published for {0}")]
    NotPublished(String),
    #[error("invalid database: {0}")]
    Invalid(String),
}

/// Which database to install. `City` also answers country, so it is the
/// default — the admin list shows both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Country,
    City,
}

impl Variant {
    /// Parse the stored setting; anything unrecognised falls back to `City`,
    /// matching the column default.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw {
            "country" => Self::Country,
            _ => Self::City,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Country => "country",
            Self::City => "city",
        }
    }
}

impl fmt::Display for Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A resolved location. Either field may be absent: country-only databases
/// never yield a city, and city databases leave plenty of ranges unresolved.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeoLocation {
    /// ISO 3166-1 alpha-2, uppercase.
    pub country_code: Option<String>,
    pub city: Option<String>,
}

impl GeoLocation {
    /// Nothing was resolved — not worth storing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.country_code.is_none() && self.city.is_none()
    }
}

/// Whether an address is one we deliberately never look up.
///
/// Private, loopback, link-local and carrier-NAT ranges have no meaningful
/// geographic answer, and on an on-premise deployment they are the common
/// case. Returning `None` for them keeps invented data out of the database;
/// the UI recognises a private address and renders "Local network".
#[must_use]
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_private_v4(mapped);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || v4.is_documentation()
        // 100.64.0.0/10 — carrier-grade NAT (RFC 6598).
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
}

/// The installed database plus the enabled flag, shared across handlers.
///
/// The reader sits behind an `RwLock` so a refresh can swap it in without a
/// restart; lookups take the read lock only long enough to clone the `Arc`.
pub struct GeoIp {
    reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
    enabled: AtomicBool,
    /// Directory holding the `.mmdb`, under the storage root.
    dir: PathBuf,
}

impl fmt::Debug for GeoIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeoIp")
            .field("enabled", &self.is_enabled())
            .field("has_database", &self.has_database())
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl GeoIp {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            reader: RwLock::new(None),
            enabled: AtomicBool::new(false),
            dir,
        }
    }

    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Mirror of `platform_settings.geoip_enabled`, refreshed at startup and
    /// whenever an admin changes it. Cached so the login path never queries
    /// settings just to decide whether to resolve.
    pub fn set_enabled(&self, value: bool) {
        self.enabled.store(value, Ordering::Relaxed);
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn has_database(&self) -> bool {
        self.reader.read().is_ok_and(|r| r.is_some())
    }

    /// Open a database file and make it live.
    ///
    /// Validation happens here: a file that does not parse never replaces the
    /// running reader, so a corrupt download cannot cost an operator a working
    /// database.
    pub fn load(&self, path: &Path) -> Result<(), GeoIpError> {
        let reader = Reader::open_readfile(path)?;
        // A database with no records is technically valid but useless, and is
        // the shape a truncated-then-padded file tends to take.
        if reader.metadata().node_count == 0 {
            return Err(GeoIpError::Invalid(
                "database contains no records".to_owned(),
            ));
        }
        {
            let mut guard = self
                .reader
                .write()
                .map_err(|_| GeoIpError::Invalid("geoip lock poisoned".to_owned()))?;
            *guard = Some(Arc::new(reader));
        }
        Ok(())
    }

    /// Drop the in-memory database (used when an admin removes it).
    pub fn unload(&self) {
        if let Ok(mut guard) = self.reader.write() {
            *guard = None;
        }
    }

    /// Resolve an address.
    ///
    /// `None` whenever geolocation is switched off, no database is installed,
    /// the address is private, or the database has no entry — the caller
    /// stores nothing in all four cases.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        if !self.is_enabled() || is_private(ip) {
            return None;
        }
        let reader = {
            let guard = self.reader.read().ok()?;
            Arc::clone(guard.as_ref()?)
        };

        // A city database is a superset of a country one, so decoding as
        // `City` handles both: against a country database the `city` field is
        // simply absent.
        let result = reader.lookup(ip).ok()?;
        let record: geoip2::City<'_> = result.decode().ok().flatten()?;

        let location = GeoLocation {
            country_code: record
                .country
                .iso_code
                .map(str::to_ascii_uppercase)
                .filter(|c| c.len() == 2),
            // Stored as published (English). Country names are localized on
            // the client from the ISO code; city names have no such mapping,
            // and the viewing admin's locale need not match the account's.
            city: record
                .city
                .names
                .english
                .or(record.city.names.german)
                .map(str::to_owned)
                .filter(|c| !c.is_empty()),
        };
        (!location.is_empty()).then_some(location)
    }
}

/// `YYYY-MM` for a moment in time — the publisher's monthly build label.
#[must_use]
pub fn month_label(at: OffsetDateTime) -> String {
    format!("{:04}-{:02}", at.year(), u8::from(at.month()))
}

/// The month before `at`, handling the January rollover.
#[must_use]
pub fn previous_month_label(at: OffsetDateTime) -> String {
    let (year, month) = if at.month() == time::Month::January {
        (at.year().saturating_sub(1), 12)
    } else {
        (at.year(), u8::from(at.month()).saturating_sub(1))
    };
    format!("{year:04}-{month:02}")
}

/// Outcome of an update attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// A new database was installed.
    Installed {
        variant: Variant,
        build_month: String,
        file_size: i64,
        sha256: String,
    },
    /// The installed database is already the newest published one.
    AlreadyCurrent,
}

/// Fetches and installs monthly database files.
///
/// `base_url` is injectable so tests exercise the whole path — download,
/// gunzip, validate, install — against a local server instead of the internet.
#[derive(Debug, Clone)]
pub struct Updater {
    client: reqwest::Client,
    base_url: String,
}

impl Updater {
    #[must_use]
    pub fn new(base_url: String) -> Self {
        Self {
            // A generous timeout: the city database is ~62 MB compressed and
            // operators are not always on fast links.
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .build()
                .unwrap_or_default(),
            base_url,
        }
    }

    /// The published URL for one monthly build.
    #[must_use]
    pub fn url_for(&self, variant: Variant, month: &str) -> String {
        format!(
            "{}/dbip-{}-lite-{month}.mmdb.gz",
            self.base_url.trim_end_matches('/'),
            variant.as_str()
        )
    }

    /// Download and gunzip one monthly build.
    ///
    /// A 404 becomes [`GeoIpError::NotPublished`] so the caller can fall back
    /// to the previous month — early in a month the current build may not
    /// exist yet.
    pub async fn fetch(&self, variant: Variant, month: &str) -> Result<Vec<u8>, GeoIpError> {
        let url = self.url_for(variant, month);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| GeoIpError::Download(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(GeoIpError::NotPublished(month.to_owned()));
        }
        if !response.status().is_success() {
            return Err(GeoIpError::Download(format!(
                "{} returned HTTP {}",
                url,
                response.status()
            )));
        }

        let compressed = response
            .bytes()
            .await
            .map_err(|e| GeoIpError::Download(e.to_string()))?;

        let mut out = Vec::new();
        flate2::read::GzDecoder::new(compressed.as_ref())
            .take(MAX_DB_BYTES)
            .read_to_end(&mut out)
            .map_err(|e| GeoIpError::Invalid(format!("could not decompress: {e}")))?;
        if out.is_empty() {
            return Err(GeoIpError::Invalid("decompressed to nothing".to_owned()));
        }
        Ok(out)
    }

    /// Install a database from raw (decompressed) bytes.
    ///
    /// Writes to a temporary file, validates by opening it, and only then
    /// renames into place and swaps the live reader — a bad file never
    /// displaces a good one. Returns the installed metadata.
    pub async fn install_bytes(
        &self,
        geoip: &GeoIp,
        variant: Variant,
        month: &str,
        bytes: &[u8],
    ) -> Result<UpdateOutcome, GeoIpError> {
        tokio::fs::create_dir_all(geoip.dir()).await?;

        let final_name = format!("dbip-{}-{month}.mmdb", variant.as_str());
        let final_path = geoip.dir().join(&final_name);
        let temp_path = geoip.dir().join(format!("{final_name}.part"));

        tokio::fs::write(&temp_path, bytes).await?;

        // Validate before it can displace the running database.
        let validation = Reader::open_readfile(&temp_path);
        match validation {
            Ok(reader) if reader.metadata().node_count > 0 => {}
            Ok(_) => {
                drop(tokio::fs::remove_file(&temp_path).await);
                return Err(GeoIpError::Invalid(
                    "database contains no records".to_owned(),
                ));
            }
            Err(e) => {
                drop(tokio::fs::remove_file(&temp_path).await);
                return Err(GeoIpError::Database(e));
            }
        }

        tokio::fs::rename(&temp_path, &final_path).await?;
        geoip.load(&final_path)?;

        // Remove superseded builds so the directory does not accumulate 62 MB
        // files month after month.
        remove_stale_files(geoip.dir(), &final_name).await;

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let sha256 = hasher
            .finalize()
            .iter()
            .fold(String::with_capacity(64), |mut acc, b| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{b:02x}");
                acc
            });

        Ok(UpdateOutcome::Installed {
            variant,
            build_month: month.to_owned(),
            file_size: i64::try_from(bytes.len()).unwrap_or(i64::MAX),
            sha256,
        })
    }

    /// Fetch the newest published build and install it.
    ///
    /// Tries the current month, then the previous one — the publisher does not
    /// post a new build on the 1st. `installed_month` short-circuits when we
    /// already hold that build and `force` is not set.
    pub async fn update(
        &self,
        geoip: &GeoIp,
        variant: Variant,
        installed_month: Option<&str>,
        force: bool,
        now: OffsetDateTime,
    ) -> Result<UpdateOutcome, GeoIpError> {
        let current = month_label(now);
        let previous = previous_month_label(now);

        if !force && installed_month == Some(current.as_str()) {
            return Ok(UpdateOutcome::AlreadyCurrent);
        }

        let mut last_err = None;
        for month in [current.as_str(), previous.as_str()] {
            if !force && installed_month == Some(month) {
                return Ok(UpdateOutcome::AlreadyCurrent);
            }
            match self.fetch(variant, month).await {
                Ok(bytes) => return self.install_bytes(geoip, variant, month, &bytes).await,
                Err(GeoIpError::NotPublished(m)) => {
                    tracing::debug!(month = %m, "geoip build not published yet, trying older");
                    last_err = Some(GeoIpError::NotPublished(m));
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or(GeoIpError::NotPublished(current)))
    }
}

/// Delete every `.mmdb` in the directory except `keep`.
async fn remove_stale_files(dir: &Path, keep: &str) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name != keep
            && (name.ends_with(".mmdb") || name.ends_with(".mmdb.part"))
            && let Err(e) = tokio::fs::remove_file(entry.path()).await
        {
            tracing::warn!(error = %e, file = %name, "failed to remove stale geoip file");
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn private_ranges_are_never_looked_up() {
        for raw in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.7",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = raw.parse().expect("test address parses");
            assert!(is_private(ip), "{raw} should be treated as private");
        }
    }

    #[test]
    fn public_addresses_are_looked_up() {
        for raw in ["8.8.8.8", "1.1.1.1", "84.75.10.20", "2001:4860:4860::8888"] {
            let ip: IpAddr = raw.parse().expect("test address parses");
            assert!(!is_private(ip), "{raw} should be treated as public");
        }
    }

    #[test]
    fn month_labels_roll_over_january() {
        let jan = time::macros::datetime!(2026-01-15 12:00 UTC);
        assert_eq!(month_label(jan), "2026-01");
        assert_eq!(previous_month_label(jan), "2025-12");

        let jul = time::macros::datetime!(2026-07-29 12:00 UTC);
        assert_eq!(month_label(jul), "2026-07");
        assert_eq!(previous_month_label(jul), "2026-06");
    }

    #[test]
    fn url_matches_the_published_layout() {
        let up = Updater::new(DEFAULT_BASE_URL.to_owned());
        assert_eq!(
            up.url_for(Variant::City, "2026-07"),
            "https://download.db-ip.com/free/dbip-city-lite-2026-07.mmdb.gz"
        );
        assert_eq!(
            up.url_for(Variant::Country, "2026-07"),
            "https://download.db-ip.com/free/dbip-country-lite-2026-07.mmdb.gz"
        );
    }

    #[test]
    fn variant_parsing_defaults_to_city() {
        assert_eq!(Variant::parse("country"), Variant::Country);
        assert_eq!(Variant::parse("city"), Variant::City);
        assert_eq!(Variant::parse("nonsense"), Variant::City);
    }

    #[test]
    fn lookup_is_inert_while_disabled_or_empty() {
        let geo = GeoIp::new(PathBuf::from("/nonexistent"));
        let ip: IpAddr = "8.8.8.8".parse().expect("test address parses");

        // Disabled and no database.
        assert!(geo.lookup(ip).is_none());

        // Enabled but still no database installed.
        geo.set_enabled(true);
        assert!(geo.lookup(ip).is_none());
        assert!(!geo.has_database());
    }

    #[test]
    fn loading_a_non_database_fails_without_installing() {
        let dir = std::env::temp_dir().join("ip-geoip-load-test");
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("garbage.mmdb");
        std::fs::write(&path, b"this is not a maxmind database").expect("write");

        let geo = GeoIp::new(dir);
        assert!(geo.load(&path).is_err());
        assert!(!geo.has_database(), "a bad file must not become live");

        drop(std::fs::remove_file(&path));
    }
}
