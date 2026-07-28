//! Atomic storage for accepted context-scoped presentation tags.

use crate::Error;
use std::collections::HashSet;

/// Atomic persistence required to enforce a scoped presentation limit.
///
/// `insert_if_absent` must be one linearizable operation across every
/// verifier replica for the same issuer and presentation scope. It must not
/// return `true` until the tag is durable. The application must perform the
/// protected action only after this operation returns `true`.
pub trait TagStore: Send {
    /// Atomically insert `(scope, tag)`.
    ///
    /// Returns `true` exactly for the caller that inserted the first durable
    /// copy, and `false` when the tag was already present.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot complete the atomic durable
    /// operation.
    fn insert_if_absent(&mut self, scope: [u8; 32], tag: [u8; 32]) -> Result<bool, Error>;
}

/// Process-local reference tag store.
///
/// Use this store for tests and examples. It is not crash-safe or shared
/// across verifier replicas. Restoring an older snapshot can admit previously
/// accepted presentations again.
#[derive(Default)]
pub struct MemoryTagStore {
    tags: HashSet<([u8; 32], [u8; 32])>,
}

impl MemoryTagStore {
    /// Number of accepted `(scope, tag)` pairs in this process.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Whether the process-local store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

impl TagStore for MemoryTagStore {
    fn insert_if_absent(&mut self, scope: [u8; 32], tag: [u8; 32]) -> Result<bool, Error> {
        Ok(self.tags.insert((scope, tag)))
    }
}
