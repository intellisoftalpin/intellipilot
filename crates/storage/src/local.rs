//! Local filesystem [`Storage`] implementation.
//!
//! Objects are addressed by an opaque, server-generated key (e.g.
//! `ab/cd/uuid`). Keys are validated to be relative and traversal-free before
//! touching disk, so a hostile key can never escape the storage root.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{ObjectReader, Storage, StorageError, StoredObject};

#[derive(Debug, Clone)]
pub struct LocalStorage {
    root: PathBuf,
}

impl LocalStorage {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve a key to an absolute path under the root, rejecting any key that
    /// would escape it (absolute paths, `..`, separators on Windows, …).
    fn resolve(&self, key: &str) -> Result<PathBuf, StorageError> {
        if key.is_empty() {
            return Err(StorageError::NotFound);
        }
        let mut path = self.root.clone();
        for component in key.split('/') {
            // Only plain, non-traversing components are allowed.
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.contains('\\')
                || component.contains('\0')
            {
                return Err(StorageError::NotFound);
            }
            path.push(component);
        }
        // Defense in depth: the final path must stay under root.
        if !path.starts_with(&self.root) {
            return Err(StorageError::NotFound);
        }
        Ok(path)
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn put(&self, key: &str, body: Bytes, mime: &str) -> Result<StoredObject, StorageError> {
        let path = self.resolve(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let size = body.len() as u64;
        let sha256_hex = {
            let mut hasher = Sha256::new();
            hasher.update(&body);
            hex::encode(hasher.finalize())
        };
        tokio::fs::write(&path, &body).await?;
        Ok(StoredObject {
            key: key.to_owned(),
            size,
            mime: mime.to_owned(),
            sha256_hex,
        })
    }

    async fn get(&self, key: &str) -> Result<Bytes, StorageError> {
        let path = self.resolve(key)?;
        match tokio::fs::read(&path).await {
            Ok(bytes) => Ok(Bytes::from(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.resolve(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// A hidden directory under the root: same filesystem as the objects, so
    /// adopting a finished upload is a rename. Object keys are server-built
    /// hex shards and can never name it.
    fn staging_dir(&self) -> PathBuf {
        self.root.join(STAGING_DIR)
    }

    async fn put_file(
        &self,
        key: &str,
        src: &Path,
        mime: &str,
    ) -> Result<StoredObject, StorageError> {
        let path = self.resolve(key)?;
        let size = tokio::fs::metadata(src).await?.len();
        if tokio::fs::try_exists(&path).await? {
            // Content-addressed: an object at this key already holds exactly
            // these bytes. Keep it and drop the spooled copy.
            tokio::fs::remove_file(src).await?;
        } else {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            if tokio::fs::rename(src, &path).await.is_err() {
                // Different filesystem (a custom staging dir): copy instead.
                tokio::fs::copy(src, &path).await?;
                tokio::fs::remove_file(src).await?;
            }
        }
        Ok(StoredObject {
            key: key.to_owned(),
            size,
            mime: mime.to_owned(),
            sha256_hex: key.rsplit('/').next().unwrap_or_default().to_owned(),
        })
    }

    async fn size(&self, key: &str) -> Result<u64, StorageError> {
        let path = self.resolve(key)?;
        match tokio::fs::metadata(&path).await {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StorageError::NotFound),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    async fn open_range(
        &self,
        key: &str,
        start: u64,
        len: u64,
    ) -> Result<ObjectReader, StorageError> {
        let path = self.resolve(key)?;
        let mut file = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound);
            }
            Err(e) => return Err(StorageError::Io(e)),
        };
        if start > 0 {
            file.seek(std::io::SeekFrom::Start(start)).await?;
        }
        Ok(Box::pin(file.take(len)))
    }

    async fn sweep_staging(&self, max_age: std::time::Duration) -> usize {
        let dir = self.root.join(STAGING_DIR);
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
            return 0;
        };
        let mut removed: usize = 0;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let old = entry
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > max_age);
            if old && tokio::fs::remove_file(entry.path()).await.is_ok() {
                removed = removed.saturating_add(1);
            }
        }
        removed
    }
}

/// Name of the upload spool directory under the storage root.
pub const STAGING_DIR: &str = ".staging";

/// Minimal hex encoder (avoids a dependency just for object hashing).
mod hex {
    pub(super) fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len().saturating_mul(2));
        for b in bytes {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
        }
        s
    }
}

/// Helper to build a sharded storage key from a uuid-like id.
#[must_use]
pub fn shard_key(id: &str) -> String {
    let safe: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    let a = safe.get(0..2).unwrap_or("00");
    let b = safe.get(2..4).unwrap_or("00");
    format!("{a}/{b}/{safe}")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("ip-storage-{}", uuid::Uuid::now_v7()))
    }

    #[tokio::test]
    async fn put_get_delete_round_trip() {
        let s = LocalStorage::new(tmp());
        let key = shard_key("abcdef12-3456");
        let obj = s
            .put(&key, Bytes::from_static(b"hello"), "text/plain")
            .await
            .unwrap();
        assert_eq!(obj.size, 5);
        assert_eq!(s.get(&key).await.unwrap(), Bytes::from_static(b"hello"));
        s.delete(&key).await.unwrap();
        assert!(matches!(s.get(&key).await, Err(StorageError::NotFound)));
    }

    #[tokio::test]
    async fn put_file_adopts_spooled_file_and_keeps_duplicates() {
        let s = LocalStorage::new(tmp());
        let staging = s.staging_dir();
        tokio::fs::create_dir_all(&staging).await.unwrap();
        let key = shard_key("0123456789abcdef");

        let first = staging.join("one");
        tokio::fs::write(&first, b"payload").await.unwrap();
        let obj = s.put_file(&key, &first, "text/plain").await.unwrap();
        assert_eq!(obj.size, 7);
        assert!(!first.exists(), "spooled file is moved, not copied");
        assert_eq!(s.get(&key).await.unwrap(), Bytes::from_static(b"payload"));

        // Same content again: the stored object is kept, the spool removed.
        let second = staging.join("two");
        tokio::fs::write(&second, b"payload").await.unwrap();
        s.put_file(&key, &second, "text/plain").await.unwrap();
        assert!(!second.exists());
        assert_eq!(s.size(&key).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn open_range_streams_the_requested_slice() {
        let s = LocalStorage::new(tmp());
        let key = shard_key("fedcba9876543210");
        s.put(&key, Bytes::from_static(b"0123456789"), "text/plain")
            .await
            .unwrap();
        let mut out = Vec::new();
        s.open_range(&key, 3, 4)
            .await
            .unwrap()
            .read_to_end(&mut out)
            .await
            .unwrap();
        assert_eq!(out, b"3456");
        assert!(matches!(
            s.open_range("aa/bb/missing", 0, 1).await,
            Err(StorageError::NotFound)
        ));
    }

    #[tokio::test]
    async fn sweep_staging_removes_only_old_spools() {
        let s = LocalStorage::new(tmp());
        let staging = s.staging_dir();
        tokio::fs::create_dir_all(&staging).await.unwrap();
        tokio::fs::write(staging.join("fresh"), b"x").await.unwrap();
        assert_eq!(
            s.sweep_staging(std::time::Duration::from_secs(3600)).await,
            0
        );
        assert_eq!(s.sweep_staging(std::time::Duration::ZERO).await, 1);
        assert!(!staging.join("fresh").exists());
    }

    #[tokio::test]
    async fn rejects_traversal_keys() {
        let s = LocalStorage::new(tmp());
        for bad in ["../escape", "/etc/passwd", "a/../../b", "", "a/./b"] {
            assert!(
                matches!(s.get(bad).await, Err(StorageError::NotFound)),
                "key {bad:?}"
            );
        }
    }
}
