//! File storage trait + impls.

use std::path::{Path, PathBuf};
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;
use tokio::io::AsyncRead;

pub mod local;
pub mod sanitize;

pub use local::{LocalStorage, shard_key};
pub use sanitize::sanitize_filename;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("too large: {size} bytes exceeds limit {limit}")]
    TooLarge { size: u64, limit: u64 },
    #[error("unsupported mime: {0}")]
    UnsupportedMime(String),
}

#[derive(Debug, Clone)]
pub struct StoredObject {
    pub key: String,
    pub size: u64,
    pub mime: String,
    pub sha256_hex: String,
}

/// A streaming reader over (part of) a stored object.
pub type ObjectReader = Pin<Box<dyn AsyncRead + Send>>;

#[async_trait]
pub trait Storage: Send + Sync + 'static {
    async fn put(&self, key: &str, body: Bytes, mime: &str) -> Result<StoredObject, StorageError>;
    async fn get(&self, key: &str) -> Result<Bytes, StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;

    /// Where an upload in progress is spooled before [`Self::put_file`]
    /// adopts it. Implementations backed by a filesystem should return a
    /// directory on the *same* filesystem as their objects, so adoption is a
    /// rename rather than a copy of a multi-gigabyte file.
    fn staging_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }

    /// Adopt a fully written, already hashed file as the object at `key`.
    /// The source file is consumed (moved or removed) on success. When an
    /// object already exists at `key` — content-addressed keys make that a
    /// duplicate upload — the existing object is kept.
    ///
    /// The default reads the file into memory and calls [`Self::put`]; the
    /// local store overrides it with a rename.
    async fn put_file(
        &self,
        key: &str,
        src: &Path,
        mime: &str,
    ) -> Result<StoredObject, StorageError> {
        let bytes = tokio::fs::read(src).await?;
        let obj = self.put(key, Bytes::from(bytes), mime).await?;
        tokio::fs::remove_file(src).await?;
        Ok(obj)
    }

    /// Size of the object in bytes.
    async fn size(&self, key: &str) -> Result<u64, StorageError> {
        self.get(key).await.map(|b| b.len() as u64)
    }

    /// Stream `len` bytes of the object starting at byte `start`. The caller
    /// validates the range against [`Self::size`].
    ///
    /// The default loads the whole object; the local store seeks instead.
    async fn open_range(
        &self,
        key: &str,
        start: u64,
        len: u64,
    ) -> Result<ObjectReader, StorageError> {
        let bytes = self.get(key).await?;
        let from = usize::try_from(start)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        let to = usize::try_from(start.saturating_add(len))
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        Ok(Box::pin(std::io::Cursor::new(bytes.slice(from..to))))
    }

    /// Remove spooled uploads older than `max_age` — leftovers of uploads
    /// interrupted before they were adopted or cleaned up. Returns the number
    /// of files removed. The default spools to the system temp dir, which it
    /// does not own, so it removes nothing.
    async fn sweep_staging(&self, _max_age: std::time::Duration) -> usize {
        0
    }
}
