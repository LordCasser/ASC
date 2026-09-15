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

/// SHA-256 over `data`, used for the artifact identity (`ArtifactId`).
///
/// Same reasoning as `sha1`: hand-rolled so the dependency set stays
/// integration-owner controlled; verified against the FIPS 180-4 vectors.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut chunks = data.chunks_exact(64);
    let mut block = [0u8; 64];
    for chunk in &mut chunks {
        block.copy_from_slice(chunk);
        sha256_compress(&mut state, &block);
    }
    let tail = chunks.remainder();
    let mut last = [0u8; 64];
    last[..tail.len()].copy_from_slice(tail);
    last[tail.len()] = 0x80;
    if tail.len() >= 56 {
        sha256_compress(&mut state, &last);
        last = [0u8; 64];
    }
    last[56..64].copy_from_slice(&bit_length.to_be_bytes());
    sha256_compress(&mut state, &last);
    let mut out = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
        0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
        0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
        0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
        0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
        0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
        0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut w = [0u32; 64];
    for (index, word) in block.chunks_exact(4).enumerate() {
        w[index] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for index in 16..64 {
        let s0 = w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 = w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for index in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[index])
            .wrapping_add(w[index]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    let add = |state: &mut [u32; 8], values: [u32; 8]| {
        for (slot, value) in state.iter_mut().zip(values) {
            *slot = slot.wrapping_add(value);
        }
    };
    add(state, [a, b, c, d, e, f, g, h]);
}

#[cfg(test)]
mod sha256_tests {
    use super::*;

    fn hex(digest: [u8; 32]) -> String {
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn sha256_matches_known_vectors() {
        // Verified against Python hashlib.sha256.
        assert_eq!(
            hex(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Multi-block + boundary cases (56 = exact padding spill,
        // 64 = block boundary), verified against Python hashlib.
        assert_eq!(
            hex(sha256(&[b'a'; 100])),
            "2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e"
        );
        assert_eq!(
            hex(sha256(&[b'a'; 56])),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            hex(sha256(&[b'a'; 64])),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }
}
