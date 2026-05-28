//! File storage trait + impls.

use async_trait::async_trait;
use bytes::Bytes;
use thiserror::Error;

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

#[async_trait]
pub trait Storage: Send + Sync + 'static {
    async fn put(&self, key: &str, body: Bytes, mime: &str) -> Result<StoredObject, StorageError>;
    async fn get(&self, key: &str) -> Result<Bytes, StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
}
