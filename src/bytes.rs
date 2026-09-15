//! Bounds-checked little-endian reads, control checkpoints and the hashing
//! primitives shared by the binary parsers.
//!
//! A02 adds the cancellation/deadline probe every bounded read or inflate loop
//! consults. The shape is deliberately minimal: A11 replaces it with the real
//! `OperationControl` (CancelToken + optional deadline) and takes over this
//! file's probe without touching the call sites' semantics.

use anyhow::Context;
use crate::error::{CancelCause, Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[inline]
pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16, anyhow::Error> {
    let bytes: [u8; 2] = data
        .get(offset..offset + 2)
        .context("truncated u16")?
        .try_into()?;
    Ok(u16::from_le_bytes(bytes))
}

#[inline]
pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32, anyhow::Error> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .context("truncated u32")?
        .try_into()?;
    Ok(u32::from_le_bytes(bytes))
}

/// Temporary stand-in for `OperationControl` (interfaces.md §5).
///
/// A02 call sites take this by reference so every read/inflate loop can check
/// cancellation at a bounded cadence; **A11 swaps this struct for the real
/// control type** and keeps the checkpoint spacing contract:
/// reads/decodes check at least once per 64 KiB of progress.
pub(crate) struct ControlProbe<'a> {
    /// Set by the host to request cancellation; observed with relaxed ordering
    /// because a missed checkpoint only delays the cancel, never loses it.
    pub(crate) cancelled: &'a AtomicBool,
    /// Absolute deadline; `None` means unlimited.
    pub(crate) deadline: Option<Instant>,
}

impl ControlProbe<'_> {
    /// A probe that never fires, for legacy callers that have no control yet.
    pub(crate) fn never() -> ControlProbe<'static> {
        static NOT_CANCELLED: AtomicBool = AtomicBool::new(false);
        ControlProbe { cancelled: &NOT_CANCELLED, deadline: None }
    }

    /// Errors with `Cancelled` once the flag is set or the deadline passed.
    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(cancelled(CancelCause::User));
        }
        if let Some(deadline) = self.deadline
            && Instant::now() >= deadline
        {
            return Err(cancelled(CancelCause::Deadline));
        }
        Ok(())
    }
}

fn cancelled(cause: CancelCause) -> Error {
    Error::new(ErrorKind::Cancelled { cause })
        .with_context(match cause {
            CancelCause::User => "operation cancelled by the user",
            CancelCause::Deadline => "operation deadline exceeded",
        })
}

/// Cadence guard for the "check at least once per 64 KiB" rule.
///
/// Owners of long loops feed the bytes produced since the last call; the probe
/// is only consulted once the accumulated progress crosses the checkpoint
/// spacing, so a 4 KiB string hash pays no atomic loads at all.
pub(crate) struct Checkpoints {
    since_check: usize,
}

/// The checkpoint spacing from interfaces.md §5.
pub(crate) const CHECKPOINT_SPACING: usize = 64 * 1024;

impl Checkpoints {
    pub(crate) fn new() -> Self {
        Checkpoints { since_check: 0 }
    }

    pub(crate) fn tick(
        &mut self,
        control: &ControlProbe<'_>,
        progress: usize,
    ) -> Result<(), Error> {
        self.since_check = self.since_check.saturating_add(progress);
        if self.since_check >= CHECKPOINT_SPACING {
            self.since_check = 0;
            return control.check();
        }
        Ok(())
    }
}

impl Default for Checkpoints {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-1 over `data`, used for the DEX header signature diagnostic.
///
/// Not used for security anywhere; the DEX format's integrity field is SHA-1
/// by definition. Implemented here (rather than via a dependency) so the
/// crate's dependency set stays integration-owner controlled. Its only caller
/// is the A02 container layer, which the binary graph does not reach until
/// A07 wires it — hence the allow.
#[allow(dead_code)]
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1 {
        state: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
        buffered: 0,
        buffer: [0; 64],
        length: 0,
    };
    hasher.update(data);
    let state = hasher.finish();
    let mut out = [0u8; 20];
    for (index, word) in out.chunks_exact_mut(4).enumerate() {
        word.copy_from_slice(&state[index].to_be_bytes());
    }
    out
}

#[allow(dead_code)]
struct Sha1 {
    state: [u32; 5],
    buffered: usize,
    buffer: [u8; 64],
    length: u64,
}

#[allow(dead_code)]
impl Sha1 {
    fn update(&mut self, data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        let mut rest = data;
        if self.buffered > 0 {
            let take = rest.len().min(64 - self.buffered);
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&rest[..take]);
            self.buffered += take;
            rest = &rest[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
            if rest.is_empty() {
                // The tail path below would clobber `buffered` to zero and
                // forget the bytes just buffered.
                return;
            }
        }
        let mut blocks = rest.chunks_exact(64);
        for block in &mut blocks {
            let mut owned = [0u8; 64];
            owned.copy_from_slice(block);
            self.compress(&owned);
        }
        self.buffer[..blocks.remainder().len()].copy_from_slice(blocks.remainder());
        self.buffered = blocks.remainder().len();
    }

    fn finish(mut self) -> [u32; 5] {
        let bit_length = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != 56 {
            self.update(&[0]);
        }
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        self.state
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut words = [0u32; 80];
        for (index, word) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for index in 16..80 {
            words[index] = (words[index - 3] ^ words[index - 8] ^ words[index - 14]
                ^ words[index - 16])
                .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_rejects_truncation() {
        let data = [0x34, 0x12, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u16(&data, 0).unwrap(), 0x1234);
        assert_eq!(read_u32(&data, 2).unwrap(), 0x1234_5678);
        assert!(read_u16(&data, 5).is_err());
        assert!(read_u32(&data, 3).is_err());
        assert!(read_u16(&[], 0).is_err());
    }

    #[test]
    fn sha1_matches_known_vectors() {
        fn hex(digest: [u8; 20]) -> String {
            digest.iter().map(|b| format!("{b:02x}")).collect()
        }
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        // Exercises the multi-block and buffering paths (100 'a' bytes).
        // Verified against Python hashlib.sha1.
        assert_eq!(
            hex(sha1(&[b'a'; 100])),
            "7f9000257a4918d7072655ea468540cdcbd42e0c"
        );
        // 64 bytes exactly: block boundary handling.
        assert_eq!(
            hex(sha1(&[b'a'; 64])),
            "0098ba824b5c16427bd7a1122a5a442a25ec644d"
        );
    }

    #[test]
    fn probe_reports_user_cancel_and_deadline() {
        let flag = AtomicBool::new(false);
        let probe = ControlProbe { cancelled: &flag, deadline: None };
        assert!(probe.check().is_ok());
        flag.store(true, Ordering::Relaxed);
        let error = probe.check().unwrap_err();
        assert!(
            matches!(error.kind(), ErrorKind::Cancelled { cause: CancelCause::User }),
            "unexpected kind: {:?}",
            error.kind()
        );

        let never = ControlProbe::never();
        assert!(never.check().is_ok());
        let expired = ControlProbe { cancelled: &flag, deadline: None };
        let _ = expired;
        let flag_off = AtomicBool::new(false);
        let past = ControlProbe {
            cancelled: &flag_off,
            deadline: Some(Instant::now() - std::time::Duration::from_millis(1)),
        };
        let error = past.check().unwrap_err();
        assert!(
            matches!(error.kind(), ErrorKind::Cancelled { cause: CancelCause::Deadline }),
            "unexpected kind: {:?}",
            error.kind()
        );
    }

    #[test]
    fn checkpoints_fire_at_most_once_per_64k() {
        let flag = AtomicBool::new(true); // already cancelled
        let probe = ControlProbe { cancelled: &flag, deadline: None };
        let mut checkpoints = Checkpoints::new();
        // Below the spacing: no check happens, so even a cancelled probe passes.
        assert!(checkpoints.tick(&probe, 1024).is_ok());
        assert!(checkpoints.tick(&probe, 1024).is_ok());
        // Crossing 64 KiB triggers the probe and surfaces the cancellation.
        assert!(checkpoints.tick(&probe, 100 * 1024).is_err());
    }
}
