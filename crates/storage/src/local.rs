//! Local filesystem [`Storage`] implementation.
//!
//! Objects are addressed by an opaque, server-generated key (e.g.
//! `ab/cd/uuid`). Keys are validated to be relative and traversal-free before
//! touching disk, so a hostile key can never escape the storage root.

use std::path::PathBuf;

use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};

use crate::{Storage, StorageError, StoredObject};

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
}

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
