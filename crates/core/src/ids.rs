//! Identifier wrappers (UUIDv7).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Generate a fresh UUIDv7. Tests should seed an injected generator instead.
#[must_use]
pub fn new_v7() -> Uuid {
    Uuid::now_v7()
}

/// Typed UUID newtype. Use via the `id!` macro to create per-entity types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Id<T: ?Sized>(
    pub Uuid,
    #[serde(skip)] core::marker::PhantomData<fn() -> T>,
);

impl<T: ?Sized> Id<T> {
    #[must_use]
    pub fn new() -> Self {
        Self(new_v7(), core::marker::PhantomData)
    }

    #[must_use]
    pub const fn from_uuid(u: Uuid) -> Self {
        Self(u, core::marker::PhantomData)
    }

    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl<T: ?Sized> Default for Id<T> {
    fn default() -> Self {
        Self::new()
    }
}
