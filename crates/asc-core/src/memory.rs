//! Deterministic accounting for allocations owned by an [`Engine`].
//!
//! The account is deliberately a byte ledger rather than an RSS claim.  A
//! permit represents one measured or conservatively bounded allocation and
//! returns its charge when the last owner drops it.  The account is shared by
//! artifacts, transient decode buffers and reports.

use crate::error::Error;
use crate::model::MemoryPermit;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct MemoryAccount {
    active: Arc<AtomicU64>,
    limit: u64,
    #[cfg(test)]
    pub(crate) peak: AtomicU64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn checked_reservation_rejects_overflow_and_returns_charge_on_drop() {
        let (account, active) = MemoryAccount::new(u64::MAX);
        let account = Arc::new(account);
        let permit = account
            .reserve_with_limit(u64::MAX, u64::MAX, "overflow fixture")
            .unwrap();
        assert_eq!(active.load(Ordering::Relaxed), u64::MAX);
        let error = account
            .reserve_with_limit(1, u64::MAX, "overflow fixture")
            .unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ResourceLimit));
        drop(permit);
        assert_eq!(active.load(Ordering::Relaxed), 0);
    }
}

impl MemoryAccount {
    pub(crate) fn new(limit: u64) -> (Self, Arc<AtomicU64>) {
        let active = Arc::new(AtomicU64::new(0));
        (
            Self {
                active: Arc::clone(&active),
                limit,
                #[cfg(test)]
                peak: AtomicU64::new(0),
            },
            active,
        )
    }

    pub(crate) fn reserve_with_limit(
        &self,
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
                    #[cfg(test)]
                    self.peak.fetch_max(next, Ordering::Relaxed);
                    return Ok(MemoryPermit::new(Arc::clone(&self.active), bytes))
                }
                Err(observed) => current = observed,
            }
        }
    }
}

#[cfg(feature = "decompile")]
impl droidsaw_dex::analysis::MemoryLease for MemoryPermit {}

#[cfg(feature = "decompile")]
impl droidsaw_dex::analysis::MemoryLedger for MemoryAccount {
    fn reserve(
        &self,
        bytes: u64,
        label: &'static str,
    ) -> Result<Box<dyn droidsaw_dex::analysis::MemoryLease>, droidsaw_dex::analysis::BackendError> {
        self.reserve_with_limit(bytes, self.limit, label)
            .map(|permit| Box::new(permit) as Box<dyn droidsaw_dex::analysis::MemoryLease>)
            .map_err(|_| droidsaw_dex::analysis::BackendError::MemoryBudget { bytes, label })
    }
}
