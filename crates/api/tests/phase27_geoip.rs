//! Phase 27 — local IP geolocation (V018).
//!
//! Covers the whole path without touching the internet: a tiny `.mmdb` is
//! built in-memory, served gzipped from a local HTTP server, downloaded,
//! validated, installed and queried.
//!
//! What is deliberately asserted:
//!   * Lookups are inert until a superadmin enables the feature — it is off by
//!     default and must stay that way.
//!   * Private addresses never resolve, so an on-premise deployment does not
//!     accumulate invented locations.
//!   * Country **and** city both come back, since the admin list shows both.
//!   * A corrupt or truncated download never displaces a working database.
//!   * A missing current month falls back to the previous one.
#![cfg(test)]
#![allow(
    let_underscore_drop,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::print_stderr,
    clippy::too_many_lines,
    clippy::let_underscore_untyped
)]

use std::collections::HashMap;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use intellipilot_api::geoip::{GeoIp, UpdateOutcome, Updater, Variant};
use maxminddb_writer::Database;
use maxminddb_writer::metadata::IpVersion;
use maxminddb_writer::paths::IpAddrWithMask;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Fixture: a three-record city database
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Names {
    en: &'static str,
}

#[derive(Serialize)]
struct CountryRec {
    iso_code: &'static str,
    names: Names,
}

#[derive(Serialize)]
struct CityRec {
    names: Names,
}

#[derive(Serialize)]
struct FullRecord {
    country: CountryRec,
    city: CityRec,
}

/// A record with a country but no city — the common shape for ranges a city
/// database cannot pin down, and the fallback the UI has to handle.
#[derive(Serialize)]
struct CountryOnlyRecord {
    country: CountryRec,
}

/// Build a small but genuine city database:
///   * `81.0.0.0/8`  → Zürich, CH (country + city)
///   * `82.0.0.0/8`  → DE only (country, no city)
///   * everything else unresolved.
fn build_test_mmdb() -> Vec<u8> {
    let mut db = Database::default();
    db.metadata.ip_version = IpVersion::V4;
    db.metadata.database_type = "DBIP-City-Lite".to_owned();
    db.metadata.languages = vec!["en".to_owned()];
    db.metadata.binary_format_major_version = 2;
    db.metadata.binary_format_minor_version = 0;

    let zurich = db
        .insert_value(FullRecord {
            country: CountryRec {
                iso_code: "CH",
                names: Names { en: "Switzerland" },
            },
            city: CityRec {
                names: Names { en: "Zürich" },
            },
        })
        .expect("insert city record");
    db.insert_node(
        IpAddrWithMask::new(IpAddr::V4(Ipv4Addr::new(81, 0, 0, 0)), 8),
        zurich,
    );

    let germany = db
        .insert_value(CountryOnlyRecord {
            country: CountryRec {
                iso_code: "DE",
                names: Names { en: "Germany" },
            },
        })
        .expect("insert country-only record");
    db.insert_node(
        IpAddrWithMask::new(IpAddr::V4(Ipv4Addr::new(82, 0, 0, 0)), 8),
        germany,
    );

    let mut out = Vec::new();
    db.write_to(&mut out).expect("serialize mmdb");
    out
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ip-geoip-{tag}-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

// ---------------------------------------------------------------------------
// A local publisher, so no test ever reaches db-ip.com
// ---------------------------------------------------------------------------

/// Serves a fixed set of paths; anything else 404s, which is exactly how the
/// real publisher behaves for a month that is not out yet.
async fn spawn_publisher(files: HashMap<String, Vec<u8>>) -> (String, tokio::task::JoinHandle<()>) {
    let files = Arc::new(files);
    let app = Router::new().route(
        "/{*path}",
        get({
            let files = Arc::clone(&files);
            move |axum::extract::Path(path): axum::extract::Path<String>| {
                let files = Arc::clone(&files);
                async move {
                    files.get(&path).map_or_else(
                        || (axum::http::StatusCode::NOT_FOUND, Vec::new()),
                        |body| (axum::http::StatusCode::OK, body.clone()),
                    )
                }
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind test publisher");
    let addr = listener.local_addr().expect("local addr");
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), handle)
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolves_country_and_city_once_enabled() {
    let dir = temp_dir("resolve");
    let geo = GeoIp::new(dir.clone());
    let path = dir.join("test.mmdb");
    std::fs::write(&path, build_test_mmdb()).expect("write fixture");
    geo.load(&path).expect("load fixture");

    // Off by default: a database being present must not start resolution.
    assert!(
        geo.lookup("81.1.2.3".parse().unwrap()).is_none(),
        "must not resolve while disabled"
    );

    geo.set_enabled(true);
    let found = geo
        .lookup("81.1.2.3".parse().unwrap())
        .expect("known address resolves");
    assert_eq!(found.country_code.as_deref(), Some("CH"));
    assert_eq!(
        found.city.as_deref(),
        Some("Zürich"),
        "the admin list shows city as well as country"
    );
}

#[tokio::test]
async fn country_without_city_is_reported_as_such() {
    let dir = temp_dir("country-only");
    let geo = GeoIp::new(dir.clone());
    let path = dir.join("test.mmdb");
    std::fs::write(&path, build_test_mmdb()).expect("write fixture");
    geo.load(&path).expect("load fixture");
    geo.set_enabled(true);

    let found = geo
        .lookup("82.5.6.7".parse().unwrap())
        .expect("address resolves to a country");
    assert_eq!(found.country_code.as_deref(), Some("DE"));
    assert!(
        found.city.is_none(),
        "no city in the database means no city in the response"
    );
}

#[tokio::test]
async fn unknown_and_private_addresses_resolve_to_nothing() {
    let dir = temp_dir("unknown");
    let geo = GeoIp::new(dir.clone());
    let path = dir.join("test.mmdb");
    std::fs::write(&path, build_test_mmdb()).expect("write fixture");
    geo.load(&path).expect("load fixture");
    geo.set_enabled(true);

    assert!(
        geo.lookup("9.9.9.9".parse().unwrap()).is_none(),
        "an address absent from the database yields nothing"
    );
    // Private ranges are the norm on-premise; inventing a location for them
    // would be worse than showing none.
    for private in ["10.0.0.1", "192.168.1.50", "127.0.0.1"] {
        assert!(
            geo.lookup(private.parse().unwrap()).is_none(),
            "{private} must never resolve"
        );
    }
}

#[tokio::test]
async fn disabling_stops_resolution_immediately() {
    let dir = temp_dir("toggle");
    let geo = GeoIp::new(dir.clone());
    let path = dir.join("test.mmdb");
    std::fs::write(&path, build_test_mmdb()).expect("write fixture");
    geo.load(&path).expect("load fixture");

    geo.set_enabled(true);
    assert!(geo.lookup("81.1.2.3".parse().unwrap()).is_some());

    geo.set_enabled(false);
    assert!(
        geo.lookup("81.1.2.3".parse().unwrap()).is_none(),
        "the kill switch must take effect without a restart"
    );
}

// ---------------------------------------------------------------------------
// Download + install
// ---------------------------------------------------------------------------

#[tokio::test]
async fn downloads_and_installs_the_current_month() {
    let mmdb = build_test_mmdb();
    let mut files = HashMap::new();
    files.insert("dbip-city-lite-2026-07.mmdb.gz".to_owned(), gzip(&mmdb));
    let (base, server) = spawn_publisher(files).await;

    let dir = temp_dir("download");
    let geo = GeoIp::new(dir.clone());
    let updater = Updater::new(base);
    let now = time::macros::datetime!(2026-07-29 12:00 UTC);

    let outcome = updater
        .update(&geo, Variant::City, None, false, now)
        .await
        .expect("update succeeds");
    match outcome {
        UpdateOutcome::Installed { build_month, .. } => assert_eq!(build_month, "2026-07"),
        UpdateOutcome::AlreadyCurrent => panic!("expected a fresh install"),
    }

    assert!(geo.has_database(), "the downloaded database becomes live");
    geo.set_enabled(true);
    let found = geo
        .lookup("81.1.2.3".parse().unwrap())
        .expect("downloaded database answers lookups");
    assert_eq!(found.country_code.as_deref(), Some("CH"));

    server.abort();
}

#[tokio::test]
async fn falls_back_to_the_previous_month() {
    // Only last month is published — the shape of the first days of a month.
    let mmdb = build_test_mmdb();
    let mut files = HashMap::new();
    files.insert("dbip-city-lite-2026-06.mmdb.gz".to_owned(), gzip(&mmdb));
    let (base, server) = spawn_publisher(files).await;

    let dir = temp_dir("fallback");
    let geo = GeoIp::new(dir.clone());
    let updater = Updater::new(base);
    let now = time::macros::datetime!(2026-07-02 09:00 UTC);

    let outcome = updater
        .update(&geo, Variant::City, None, false, now)
        .await
        .expect("falls back rather than failing");
    match outcome {
        UpdateOutcome::Installed { build_month, .. } => assert_eq!(build_month, "2026-06"),
        UpdateOutcome::AlreadyCurrent => panic!("expected the previous month to install"),
    }

    server.abort();
}

#[tokio::test]
async fn already_current_skips_the_download() {
    // Nothing is served: reaching the network at all would fail the test.
    let (base, server) = spawn_publisher(HashMap::new()).await;

    let dir = temp_dir("current");
    let geo = GeoIp::new(dir.clone());
    let updater = Updater::new(base);
    let now = time::macros::datetime!(2026-07-29 12:00 UTC);

    let outcome = updater
        .update(&geo, Variant::City, Some("2026-07"), false, now)
        .await
        .expect("no work to do");
    assert_eq!(outcome, UpdateOutcome::AlreadyCurrent);

    server.abort();
}

#[tokio::test]
async fn a_corrupt_download_never_displaces_a_working_database() {
    let mmdb = build_test_mmdb();
    let mut files = HashMap::new();
    // Valid gzip, but the payload is not a database.
    files.insert(
        "dbip-city-lite-2026-08.mmdb.gz".to_owned(),
        gzip(b"absolutely not a maxmind database"),
    );
    let (base, server) = spawn_publisher(files).await;

    let dir = temp_dir("corrupt");
    let geo = GeoIp::new(dir.clone());
    // Install a good database first.
    let good = dir.join("good.mmdb");
    std::fs::write(&good, &mmdb).expect("write fixture");
    geo.load(&good).expect("load fixture");
    geo.set_enabled(true);

    let updater = Updater::new(base);
    let now = time::macros::datetime!(2026-08-10 12:00 UTC);
    let result = updater
        .update(&geo, Variant::City, Some("2026-07"), true, now)
        .await;
    assert!(result.is_err(), "a corrupt payload must be rejected");

    // The previously working database must still be answering.
    let found = geo
        .lookup("81.1.2.3".parse().unwrap())
        .expect("the good database survives a bad download");
    assert_eq!(found.country_code.as_deref(), Some("CH"));

    server.abort();
}

#[tokio::test]
async fn a_missing_database_is_reported_not_panicked() {
    let (base, server) = spawn_publisher(HashMap::new()).await;

    let dir = temp_dir("missing");
    let geo = GeoIp::new(dir.clone());
    let updater = Updater::new(base);
    let now = time::macros::datetime!(2026-07-29 12:00 UTC);

    let result = updater.update(&geo, Variant::City, None, false, now).await;
    assert!(
        result.is_err(),
        "neither month published should surface as an error"
    );
    assert!(!geo.has_database());

    server.abort();
}

#[tokio::test]
async fn installing_replaces_the_previous_file_on_disk() {
    let mmdb = build_test_mmdb();
    let mut files = HashMap::new();
    files.insert("dbip-city-lite-2026-07.mmdb.gz".to_owned(), gzip(&mmdb));
    files.insert("dbip-city-lite-2026-08.mmdb.gz".to_owned(), gzip(&mmdb));
    let (base, server) = spawn_publisher(files).await;

    let dir = temp_dir("replace");
    let geo = GeoIp::new(dir.clone());
    let updater = Updater::new(base);

    updater
        .update(
            &geo,
            Variant::City,
            None,
            false,
            time::macros::datetime!(2026-07-29 12:00 UTC),
        )
        .await
        .expect("first install");
    updater
        .update(
            &geo,
            Variant::City,
            Some("2026-07"),
            false,
            time::macros::datetime!(2026-08-05 12:00 UTC),
        )
        .await
        .expect("second install");

    // Only the newest build should remain — 62 MB files must not pile up.
    let remaining: Vec<String> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(std::result::Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e == "mmdb")
        })
        .collect();
    assert_eq!(
        remaining,
        vec!["dbip-city-2026-08.mmdb".to_owned()],
        "superseded builds should be cleaned up"
    );

    server.abort();
}
