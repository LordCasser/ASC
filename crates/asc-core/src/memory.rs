//! Deterministic accounting for allocations owned by an [`Engine`].
//!
//! The account is deliberately a byte ledger rather than an RSS claim.  A
//! permit represents one measured or conservatively bounded allocation and
//! returns its charge when the last owner drops it.  The account is shared by
//! artifacts, transient decode buffers and reports.

use crate::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct MemoryAccount {
    active: Arc<AtomicU64>,
    limit: u64,
}

impl MemoryAccount {
    pub(crate) fn new(limit: u64) -> (Self, Arc<AtomicU64>) {
        let active = Arc::new(AtomicU64::new(0));
        (
            Self {
                active: Arc::clone(&active),
                limit,
            },
            active,
        )
    }

    pub(crate) fn reserve(self: &Arc<Self>, bytes: u64, label: &str) -> Result<MemoryPermit, Error> {
        self.reserve_with_limit(bytes, self.limit, label)
    }

    pub(crate) fn reserve_with_limit(
        self: &Arc<Self>,
        bytes: u64,
        limit: u64,
        label: &str,
    ) -> Result<MemoryPermit, Error> {
        let limit = self.limit.min(limit);
        let mut current = self.active.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(bytes).ok_or_else(|| {
                Error::resource_limit(format!(
                    "engine-owned allocation {label} overflows at {current} + {bytes} bytes"
                ))
            })?;
            if next > limit {
                return Err(Error::resource_limit(format!(
                    "engine-owned allocation {label} reaches {next} bytes, above the {} byte limit",
                    limit
                )));
            }
            match self.active.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(MemoryPermit {
                        allocation: Arc::new(Allocation {
                            account: Arc::clone(self),
                            bytes,
                        }),
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct Allocation {
    account: Arc<MemoryAccount>,
    bytes: u64,
}

impl Drop for Allocation {
    fn drop(&mut self) {
        self.account
            .active
            .fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

/// A cloneable RAII charge. Clones share the same allocation and therefore
/// keep the charge alive until the final clone is dropped.
#[derive(Clone, Debug)]
pub(crate) struct MemoryPermit {
    allocation: Arc<Allocation>,
}

impl MemoryPermit {
    pub(crate) fn bytes(&self) -> u64 {
        self.allocation.bytes
    }
}
