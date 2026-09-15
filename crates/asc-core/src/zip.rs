//! ZIP container codec: end-of-central-directory discovery, central-directory
//! entries and per-entry inflation.
//!
//! [`parse_catalog`] builds a fully validated central-directory catalog
//! (single volume, no encryption, ZIP64 explicitly rejected, bounded entry
//! count — enforced inside the directory walk, not just against the EOCD
//! count) and [`read_entry`] decodes one entry with local-header/central-
//! directory agreement, data-descriptor verification, exact-size and CRC
//! checks, resource limits and cancellation checkpoints. [`select_root_dexes`]
//! applies the root `classes*.dex` / `*.dex` discovery rules on raw name
//! bytes and keeps duplicate names with their original ordinals for the
//! upper layer (A07 owns the final selection policy).
//!
//! The pre-A02 permissive bridge (`parse_zip_entries`, `inflate_entry`,
//! `inflate_until`) was removed with its call sites; it never verified CRCs
//! and carried no resource limits.

use crate::bytes::{CHECKPOINT_SPACING, Checkpoints, ControlProbe, read_u16, read_u32};
use crate::error::{Error, ErrorKind};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Target-contract types (IN-02)
// ---------------------------------------------------------------------------

/// Resource limits enforced on the read/decode path; initial defaults from
/// interfaces.md §5. Every field is a finite positive number and all
/// arithmetic around it is checked.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InputLimits {
    /// Maximum actual decoded bytes of a single entry.
    pub(crate) max_entry_bytes: u64,
    /// Per-operation accumulated decoded bytes across entries.
    pub(crate) max_total_decoded_bytes: u64,
    /// Maximum number of central-directory entries in one archive.
    pub(crate) max_archive_entries: usize,
}

impl InputLimits {
    pub(crate) const DEFAULT: InputLimits = InputLimits {
        max_entry_bytes: 256u64 * 1024 * 1024,
        max_total_decoded_bytes: 1024u64 * 1024 * 1024,
        max_archive_entries: 100_000,
    };
}

impl Default for InputLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One central-directory record, raw bytes preserved. Ordinals are the
/// position in the unsorted central directory (the DexId entry ordinal).
#[derive(Clone, Debug)]
pub(crate) struct ArchiveEntry {
    pub(crate) ordinal: u32,
    pub(crate) raw_name: Vec<u8>,
    pub(crate) method: u16,
    pub(crate) flags: u16,
    pub(crate) crc32: u32,
    pub(crate) compressed_size: u32,
    pub(crate) uncompressed_size: u32,
    pub(crate) local_header_offset: u32,
    pub(crate) directory: bool,
}

impl ArchiveEntry {
    /// Display form: valid UTF-8 preferred, otherwise per-byte escapes. Never
    /// used as a matching key (selection works on the raw bytes).
    pub(crate) fn display(&self) -> String {
        display_name(&self.raw_name)
    }

    /// The central-directory uncompressed size. The exact-size decode
    /// contract in [`read_entry`] makes this the authoritative output length,
    /// so callers can budget against it before decoding.
    pub(crate) fn declared_uncompressed_bytes(&self) -> u64 {
        u64::from(self.uncompressed_size)
    }
}

/// A name carried by more than one central-directory record, with every
/// original ordinal. Keeping all records is deliberate: which copy wins is a
/// upper-layer (A07) policy, the catalog only reports the facts.
#[derive(Clone, Debug)]
pub(crate) struct DuplicateName {
    pub(crate) name: Vec<u8>,
    /// Contract-test surface (the input contract suite compiles this file in
    /// and asserts every original ordinal).
    #[allow(dead_code)]
    pub(crate) ordinals: Vec<u32>,
}

/// The validated archive catalog: every central-directory entry in CD order.
#[derive(Clone, Debug, Default)]
pub(crate) struct ArchiveCatalog {
    pub(crate) entries: Vec<ArchiveEntry>,
}

impl ArchiveCatalog {
    /// Conservative owned-memory estimate for the retained central-directory
    /// records. It covers each record and its owned raw name; transient ZIP
    /// parser buffers are accounted at their actual phase boundary.
    pub(crate) fn estimated_bytes(&self) -> u64 {
        self.entries.iter().fold(0u64, |total, entry| {
            total
                .saturating_add(64)
                .saturating_add(entry.raw_name.len() as u64)
        })
    }
}

/// Display form of a raw ZIP name: valid UTF-8 when possible, otherwise each
/// byte escaped as `\xNN` — never a lossy key. Control characters are escaped
/// in both branches: entry names reach diagnostics and stderr verbatim, and a
/// raw ESC/CR/LF inside a name must not be able to forge terminal output or
/// log lines.
pub(crate) fn display_name(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(text) => {
            if text.chars().any(char::is_control) {
                text.chars()
                    .map(|character| {
                        if character.is_control() {
                            format!("\\u{{{:x}}}", u32::from(character))
                        } else {
                            character.to_string()
                        }
                    })
                    .collect()
            } else {
                text.to_owned()
            }
        }
        Err(_) => raw.iter().map(|byte| format!("\\x{byte:02x}")).collect(),
    }
}

/// Offset of the EOCD record signature inside an archive, searching the
/// standard window from the end (EOCD is 22 bytes, comments up to 65_535).
fn find_eocd(data: &[u8]) -> Option<usize> {
    let search_start = data.len().saturating_sub(65_557);
    data[search_start..]
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .map(|position| position + search_start)
}

fn malformed(message: impl Into<String>) -> Error {
    Error::malformed_input(message)
}

fn unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::UnsupportedFormat).with_context(message)
}

/// Parses and validates the whole central directory.
///
/// Archive-level rejections (single volume only, no ZIP64 anywhere, no
/// encrypted entries) happen here so that a catalog result means "every
/// record is readable and decodable by this reader's support matrix". Bad
/// structure returns errors that name the failing offset or entry; it never
/// returns an empty catalog for a broken archive.
#[cfg(test)]
pub(crate) fn parse_catalog(data: &[u8], limits: &InputLimits) -> Result<ArchiveCatalog, Error> {
    parse_catalog_controlled(data, limits, &ControlProbe::never())
}

pub(crate) fn parse_catalog_controlled(
    data: &[u8],
    limits: &InputLimits,
    control: &ControlProbe<'_>,
) -> Result<ArchiveCatalog, Error> {
    control.check()?;
    let Some(eocd) = find_eocd(data) else {
        return Err(malformed(format!(
            "end of central directory not found in the last {} bytes of a {} byte archive",
            65_557.min(data.len()),
            data.len()
        )));
    };
    if eocd + 22 > data.len() {
        return Err(malformed(format!(
            "end of central directory at offset {eocd} is truncated"
        )));
    }
    let disk_number = read_u16(data, eocd + 4).map_err(|_| truncated_eocd(eocd))?;
    let cd_disk_number = read_u16(data, eocd + 6).map_err(|_| truncated_eocd(eocd))?;
    if disk_number != 0 || cd_disk_number != 0 {
        return Err(unsupported(format!(
            "multi-volume archive: EOCD at offset {eocd} declares disk {disk_number} \
             with the central directory on disk {cd_disk_number}"
        )));
    }
    let count_this = read_u16(data, eocd + 8).map_err(|_| truncated_eocd(eocd))?;
    let count_total = read_u16(data, eocd + 10).map_err(|_| truncated_eocd(eocd))?;
    if count_this == 0xFFFF || count_total == 0xFFFF {
        return Err(unsupported(format!(
            "ZIP64 archive: the EOCD at offset {eocd} carries the 0xFFFF entry-count \
             placeholder (this reader supports single-volume non-ZIP64 archives only)"
        )));
    }
    if count_this != count_total {
        return Err(malformed(format!(
            "EOCD at offset {eocd} declares {count_this} entries on this disk but \
             {count_total} in total"
        )));
    }
    if usize::from(count_this) > limits.max_archive_entries {
        return Err(Error::resource_limit(format!(
            "archive declares {} central-directory entries, above the {} limit",
            count_this, limits.max_archive_entries
        )));
    }
    let cd_size = u64::from(read_u32(data, eocd + 12).map_err(|_| truncated_eocd(eocd))?);
    let cd_offset = u64::from(read_u32(data, eocd + 16).map_err(|_| truncated_eocd(eocd))?);
    if cd_size == u64::from(u32::MAX) || cd_offset == u64::from(u32::MAX) {
        return Err(unsupported(format!(
            "ZIP64 archive: the EOCD at offset {eocd} carries a 0xFFFFFFFF size/offset \
             placeholder (this reader supports single-volume non-ZIP64 archives only)"
        )));
    }
    let cd_end = cd_offset.checked_add(cd_size).ok_or_else(|| {
        malformed(format!(
            "central directory range at offset {cd_offset} (size {cd_size}) overflows"
        ))
    })?;
    // The central directory is immediately followed by the EOCD in every
    // archive this reader accepts, so the declared range must end flush with
    // the EOCD position. Anything else (an offset into the local entries, an
    // overshoot past the EOCD) is a located structural error.
    if cd_end != eocd as u64 {
        return Err(malformed(format!(
            "central directory range [{cd_offset}..{cd_end}] declared by the EOCD at offset \
             {eocd} does not end flush with the EOCD: the directory overlaps the local \
             entries or reaches past the EOCD"
        )));
    }

    let mut entries = Vec::new();
    let mut offset = cd_offset as usize;
    let cd_end = cd_end as usize;
    while offset < cd_end {
        control.check()?;
        let ordinal = entries.len() as u32;
        let header = data.get(offset..offset + 46).ok_or_else(|| {
            malformed(format!(
                "central-directory record #{ordinal} at offset {offset} is truncated"
            ))
        })?;
        if &header[..4] != b"PK\x01\x02" {
            return Err(malformed(format!(
                "central-directory record #{ordinal} at offset {offset} has signature \
                 0x{}{}{}{} instead of PK\\x01\\x02",
                header[0], header[1], header[2], header[3]
            )));
        }
        let name_len = u16::from_le_bytes([header[28], header[29]]) as usize;
        let extra_len = u16::from_le_bytes([header[30], header[31]]) as usize;
        let comment_len = u16::from_le_bytes([header[32], header[33]]) as usize;
        let name_start = offset.checked_add(46).expect("offset + 46 is small");
        let name_end = name_start.checked_add(name_len).ok_or_else(|| {
            malformed(format!(
                "name length of entry #{ordinal} at offset {offset} overflows"
            ))
        })?;
        if name_end > cd_end {
            return Err(malformed(format!(
                "name of central-directory record #{ordinal} (length {name_len}) reaches \
                 past the directory end at offset {cd_end}"
            )));
        }
        let next = name_end
            .checked_add(extra_len)
            .and_then(|value| value.checked_add(comment_len))
            .ok_or_else(|| {
                malformed(format!(
                    "extra/comment length of entry #{ordinal} at offset {offset} overflows"
                ))
            })?;
        if next > cd_end {
            return Err(malformed(format!(
                "record #{ordinal} at offset {offset} (extra {extra_len}, comment \
                 {comment_len}) reaches past the directory end at offset {cd_end}"
            )));
        }
        let name = display_name(&data[name_start..name_end]);
        let version_needed = u16::from_le_bytes([header[6], header[7]]);
        if version_needed >= 45 {
            return Err(unsupported(format!(
                "ZIP64 archive: entry #{ordinal} ({name}) needs version {version_needed}.0"
            )));
        }
        let flags = u16::from_le_bytes([header[8], header[9]]);
        if flags & 0x0001 != 0 {
            return Err(unsupported(format!(
                "entry #{ordinal} ({name}) is encrypted (general-purpose flag bit 0)"
            )));
        }
        let method = u16::from_le_bytes([header[10], header[11]]);
        let version_made_by = u16::from_le_bytes([header[4], header[5]]);
        let external_attributes = u32::from_le_bytes(header[38..42].try_into().expect("4 bytes"));
        let crc32 = u32::from_le_bytes(header[16..20].try_into().expect("4 bytes"));
        let compressed_size = u32::from_le_bytes(header[20..24].try_into().expect("4 bytes"));
        let uncompressed_size = u32::from_le_bytes(header[24..28].try_into().expect("4 bytes"));
        if compressed_size == u32::MAX || uncompressed_size == u32::MAX {
            return Err(unsupported(format!(
                "ZIP64 archive: entry #{ordinal} ({name}) carries a 0xFFFFFFFF size placeholder"
            )));
        }
        let local_header_offset = u32::from_le_bytes(header[42..46].try_into().expect("4 bytes"));
        if local_header_offset == u32::MAX {
            return Err(unsupported(format!(
                "ZIP64 archive: entry #{ordinal} ({name}) carries the 0xFFFFFFFF \
                 local-header-offset placeholder"
            )));
        }
        let unix_mode = if version_made_by >> 8 == 3 {
            external_attributes >> 16
        } else {
            0
        };
        let directory = data[name_start..name_end].ends_with(b"/")
            || external_attributes & 0x10 != 0
            || unix_mode & 0xf000 == 0x4000;
        entries.push(ArchiveEntry {
            ordinal,
            raw_name: data[name_start..name_end].to_vec(),
            method,
            flags,
            crc32,
            compressed_size,
            uncompressed_size,
            local_header_offset,
            directory,
        });
        // Enforced inside the walk: the EOCD count above only bounds what the
        // archive *declares*, so a small declared count in front of a packed
        // directory must not be walked to completion first.
        if entries.len() > limits.max_archive_entries {
            return Err(Error::resource_limit(format!(
                "the central directory holds more than {} entries (record #{ordinal} at offset \
                 {offset} crosses the limit)",
                limits.max_archive_entries
            )));
        }
        offset = next;
    }
    if offset != cd_end {
        return Err(malformed(format!(
            "central directory walk ended at offset {offset} but the EOCD declares the \
             range ends at {cd_end}"
        )));
    }
    if entries.len() != usize::from(count_this) {
        return Err(malformed(format!(
            "EOCD declares {} entries, the directory holds {}",
            count_this,
            entries.len()
        )));
    }

    Ok(ArchiveCatalog { entries })
}

fn truncated_eocd(eocd: usize) -> Error {
    malformed(format!(
        "end of central directory at offset {eocd} is truncated"
    ))
}

/// Key general-purpose flags that must agree between the local header and the
/// central directory: encrypted (0), data descriptor (3), patched (5),
/// strong encryption (6), masked headers (13).
const KEY_FLAGS: u16 = 0x20A9;
/// The optional data-descriptor signature.
const DESCRIPTOR_SIGNATURE: u32 = 0x0807_4B50;

/// Decodes one entry under the full IN-02 contract into an owned buffer.
pub(crate) fn read_entry(
    data: &[u8],
    entry: &ArchiveEntry,
    limits: &InputLimits,
    decoded_bytes: &AtomicU64,
    control: &ControlProbe<'_>,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    read_entry_to(data, entry, limits, decoded_bytes, control, &mut output)?;
    Ok(output)
}

/// Cheap content probe used by `MethodScope::AllDetected`. It reads only the
/// first DEX magic bytes from stored or deflated output and leaves full CRC,
/// size and structural validation to the selected operation.
pub(crate) fn entry_starts_with_dex_magic(data: &[u8], entry: &ArchiveEntry) -> bool {
    let local_offset = entry.local_header_offset as usize;
    let Some(local) = data.get(local_offset..local_offset.saturating_add(30)) else {
        return false;
    };
    if local.get(..4) != Some(b"PK\x03\x04") {
        return false;
    }
    let name_len = u16::from_le_bytes([local[26], local[27]]) as usize;
    let extra_len = u16::from_le_bytes([local[28], local[29]]) as usize;
    let Some(data_start) = local_offset
        .checked_add(30)
        .and_then(|offset| offset.checked_add(name_len))
        .and_then(|offset| offset.checked_add(extra_len))
    else {
        return false;
    };
    let Some(data_end) = data_start.checked_add(entry.compressed_size as usize) else {
        return false;
    };
    let Some(compressed) = data.get(data_start..data_end) else {
        return false;
    };
    let mut prefix = [0u8; 8];
    let count = match entry.method {
        STORED => compressed.len().min(prefix.len()),
        DEFLATE => {
            let mut decoder = flate2::read::DeflateDecoder::new(compressed);
            match std::io::Read::read(&mut decoder, &mut prefix) {
                Ok(count) => count,
                Err(_) => return false,
            }
        }
        _ => return false,
    };
    let prefix = &prefix[..count];
    prefix.get(..4) == Some(b"dex\n") || prefix.get(..4) == Some(b"cdex")
}

/// Decodes one entry into a caller-provided sink under the full IN-02
/// contract. The sink only receives bytes after the declared size reservation
/// succeeds; CRC, exact-size, local-header and descriptor checks still run
/// after the final bytes have been written. Callers must discard their sink on
/// any error because a writer cannot retract bytes already accepted.
#[allow(clippy::too_many_lines)]
pub(crate) fn read_entry_to<W: Write>(
    data: &[u8],
    entry: &ArchiveEntry,
    limits: &InputLimits,
    decoded_bytes: &AtomicU64,
    control: &ControlProbe<'_>,
    writer: &mut W,
) -> Result<u64, Error> {
    control.check()?;
    let name = entry.display();
    let local_offset = entry.local_header_offset as usize;
    let local = data.get(local_offset..local_offset + 30).ok_or_else(|| {
        malformed(format!(
            "entry {name}: local header offset {local_offset} is outside the archive"
        ))
    })?;
    if &local[..4] != b"PK\x03\x04" {
        return Err(malformed(format!(
            "entry {name}: no local header signature at offset {local_offset}"
        )));
    }
    let local_version = u16::from_le_bytes([local[4], local[5]]);
    let local_flags = u16::from_le_bytes([local[6], local[7]]);
    let local_method = u16::from_le_bytes([local[8], local[9]]);
    let local_crc = u32::from_le_bytes(local[14..18].try_into().expect("4 bytes"));
    let local_compressed = u32::from_le_bytes(local[18..22].try_into().expect("4 bytes"));
    let local_uncompressed = u32::from_le_bytes(local[22..26].try_into().expect("4 bytes"));
    let name_len = u16::from_le_bytes([local[26], local[27]]) as usize;
    let extra_len = u16::from_le_bytes([local[28], local[29]]) as usize;

    let data_start = local_offset
        .checked_add(30)
        .and_then(|value| value.checked_add(name_len))
        .and_then(|value| value.checked_add(extra_len))
        .ok_or_else(|| malformed(format!("entry {name}: local header lengths overflow")))?;
    let local_name = data
        .get(local_offset + 30..data_start - extra_len)
        .ok_or_else(|| {
            malformed(format!(
                "entry {name}: local header name at offset {local_offset} is truncated"
            ))
        })?;
    if local_name != entry.raw_name {
        return Err(malformed(format!(
            "entry {name}: local header name at offset {local_offset} disagrees with the \
             central-directory name"
        )));
    }
    if local_method != entry.method {
        return Err(malformed(format!(
            "entry {name}: local header method {local_method} disagrees with the \
             central-directory method {}",
            entry.method
        )));
    }
    if local_flags & KEY_FLAGS != entry.flags & KEY_FLAGS {
        return Err(malformed(format!(
            "entry {name}: local header flags 0x{:04x} disagree with the central-directory \
             flags 0x{:04x} on key bits",
            local_flags, entry.flags
        )));
    }
    if local_flags & 0x0001 != 0 {
        return Err(unsupported(format!(
            "entry {name} is encrypted (flag bit 0)"
        )));
    }
    if local_version >= 45 {
        return Err(unsupported(format!(
            "ZIP64 archive: entry {name} needs version {local_version}.0"
        )));
    }
    let descriptor = local_flags & 0x0008 != 0;

    let declared = u64::from(entry.uncompressed_size);
    if declared > limits.max_entry_bytes {
        return Err(Error::resource_limit(format!(
            "entry {name} declares {declared} uncompressed bytes, above the {} single-entry \
             limit",
            limits.max_entry_bytes
        )));
    }
    let declared = declared as usize;
    let compressed_size = entry.compressed_size as usize;
    let data_end = data_start.checked_add(compressed_size).ok_or_else(|| {
        malformed(format!(
            "entry {name}: compressed-data range at offset {data_start} overflows"
        ))
    })?;
    if data_end > data.len() {
        return Err(malformed(format!(
            "entry {name}: compressed data [{}..{}] reaches past the {} byte archive",
            data_start,
            data_end,
            data.len()
        )));
    }
    let compressed = &data[data_start..data_end];

    // Reserve the declared output before any decode work: the exact-size
    // contract below guarantees `produced == declared` on success, so the
    // reservation is exact and an over-cap entry is rejected before its
    // buffer is allocated, not after.
    let declared_u64 = declared as u64;
    reserve_decoded_bytes(
        decoded_bytes,
        declared_u64,
        limits.max_total_decoded_bytes,
        &name,
    )?;

    let decoded = (|| -> Result<u64, Error> {
        let mut sink = EntrySink::new(writer, declared_u64, &name);
        match entry.method {
            STORED => {
                if compressed_size != declared {
                    return Err(malformed(format!(
                        "entry {name}: stored sizes disagree (compressed {compressed_size}, \
                        uncompressed {declared})"
                    )));
                }
                copy_chunked_to(compressed, &mut sink, control)?;
            }
            DEFLATE => inflate_strict_to(compressed, declared, &name, control, &mut sink)?,
            method => {
                return Err(unsupported(format!(
                    "entry {name} uses compression method {method} (only Stored (0) and \
                     Deflate (8) are supported)"
                )));
            }
        }
        debug_assert_eq!(sink.produced(), declared_u64);

        let crc = sink.crc32();
        if crc != entry.crc32 {
            return Err(malformed(format!(
                "entry {name}: CRC-32 mismatch (local header at offset {local_offset}, data at \
                 offset {data_start}): stored 0x{:08x}, computed 0x{crc:08x}",
                entry.crc32
            )));
        }
        // Without the descriptor flag the local header carries CRC/sizes too; a
        // disagreement with the directory (or, after the checks above, with the
        // actual stream) is structural. This runs after the stream checks so a
        // tampered central-directory size reports the decode-level error first.
        if !descriptor
            && (local_crc != entry.crc32
                || local_compressed != entry.compressed_size
                || local_uncompressed != entry.uncompressed_size)
        {
            return Err(malformed(format!(
                "entry {name}: local header CRC/sizes disagree with the central directory"
            )));
        }
        if descriptor {
            verify_descriptor(data, data_end, entry, &name, crc)?;
        }
        Ok(sink.produced())
    })();
    match decoded {
        Ok(output) => Ok(output),
        Err(error) => {
            release_decoded_bytes(decoded_bytes, declared_u64);
            Err(error)
        }
    }
}

const STORED: u16 = 0;
const DEFLATE: u16 = 8;

/// Verifies the data descriptor that follows a streamed entry's data.
///
/// Both spellings are legal: with the optional `0x08074b50` signature and
/// without. Every value must agree with the actual stream and the central
/// directory.
fn verify_descriptor(
    data: &[u8],
    data_end: usize,
    entry: &ArchiveEntry,
    name: &str,
    actual_crc: u32,
) -> Result<(), Error> {
    let mut position = data_end;
    if data.get(position..position + 4) == Some(&DESCRIPTOR_SIGNATURE.to_le_bytes()) {
        position += 4;
    }
    let fields = data.get(position..position + 12).ok_or_else(|| {
        malformed(format!(
            "entry {name}: data descriptor at offset {data_end} is truncated"
        ))
    })?;
    let d_crc = u32::from_le_bytes(fields[0..4].try_into().expect("4 bytes"));
    let d_compressed = u32::from_le_bytes(fields[4..8].try_into().expect("4 bytes"));
    let d_uncompressed = u32::from_le_bytes(fields[8..12].try_into().expect("4 bytes"));
    if d_crc != actual_crc
        || d_compressed != entry.compressed_size
        || d_uncompressed != entry.uncompressed_size
    {
        return Err(malformed(format!(
            "entry {name}: data descriptor at offset {data_end} (crc 0x{d_crc:08x}, sizes \
             {d_compressed}/{d_uncompressed}) disagrees with the actual stream (crc \
             0x{actual_crc:08x}, sizes {}/{})",
            entry.compressed_size, entry.uncompressed_size
        )));
    }
    Ok(())
}

fn reserve_decoded_bytes(
    decoded_bytes: &AtomicU64,
    declared: u64,
    max: u64,
    name: &str,
) -> Result<(), Error> {
    let mut current = decoded_bytes.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(declared) else {
            return Err(Error::resource_limit(format!(
                "decoded bytes overflow while reading {name}"
            )));
        };
        if next > max {
            return Err(Error::resource_limit(format!(
                "decoded bytes reach {next} across entries, above the {max} per-operation limit \
                 (while reading {name})"
            )));
        }
        match decoded_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

fn release_decoded_bytes(decoded_bytes: &AtomicU64, declared: u64) {
    decoded_bytes.fetch_sub(declared, Ordering::Relaxed);
}

struct EntrySink<'a, W> {
    writer: &'a mut W,
    declared: u64,
    produced: u64,
    crc: flate2::Crc,
    name: String,
}

impl<'a, W: Write> EntrySink<'a, W> {
    fn new(writer: &'a mut W, declared: u64, name: &str) -> Self {
        Self {
            writer,
            declared,
            produced: 0,
            crc: flate2::Crc::new(),
            name: name.to_owned(),
        }
    }

    fn push(&mut self, bytes: &[u8], control: &ControlProbe<'_>) -> Result<(), Error> {
        control.check()?;
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let Some(next) = self.produced.checked_add(len) else {
            return Err(malformed(format!(
                "entry {}: decoded byte count overflows",
                self.name
            )));
        };
        if next > self.declared {
            return Err(malformed(format!(
                "entry {}: decoded {next} bytes exceed the declared {} (trailing stream)",
                self.name, self.declared
            )));
        }
        self.writer
            .write_all(bytes)
            .map_err(|error| malformed(format!("entry {}: writer failed: {error}", self.name)))?;
        self.crc.update(bytes);
        self.produced = next;
        control.check()?;
        Ok(())
    }

    fn produced(&self) -> u64 {
        self.produced
    }

    fn crc32(&self) -> u32 {
        self.crc.sum()
    }
}

/// A stored entry's bytes, checkpointed while copying (multi-hundred-MiB
/// stored DEX entries are normal).
fn copy_chunked_to<W: Write>(
    compressed: &[u8],
    sink: &mut EntrySink<'_, W>,
    control: &ControlProbe<'_>,
) -> Result<(), Error> {
    let mut checkpoints = Checkpoints::new();
    for chunk in compressed.chunks(CHECKPOINT_SPACING) {
        sink.push(chunk, control)?;
        checkpoints.tick(control, chunk.len())?;
    }
    Ok(())
}

/// Unchecked CRC-32 for test builders (no budget checkpoints).
#[cfg(test)]
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(bytes);
    crc.sum()
}

/// Inflates a raw deflate stream under the exact-size contract.
///
/// The stream must consume the whole compressed slice, produce exactly
/// `declared` bytes, and end cleanly: a stream that ends early (truncated),
/// leaves compressed bytes after its end (trailing stream) or produces more
/// than declared is a structural error naming the entry.
fn inflate_strict_to<W: Write>(
    compressed: &[u8],
    declared: usize,
    name: &str,
    control: &ControlProbe<'_>,
    sink: &mut EntrySink<'_, W>,
) -> Result<(), Error> {
    const CHUNK: usize = 64 * 1024;

    let mut decompressor = flate2::Decompress::new(false);
    let mut output = vec![0u8; CHUNK];
    let mut checkpoints = Checkpoints::new();
    loop {
        control.check()?;
        let room = CHUNK.min(
            declared
                .saturating_sub(sink.produced() as usize)
                .saturating_add(1),
        );
        let before_in = decompressor.total_in() as usize;
        let status = decompressor
            .decompress(
                &compressed[before_in..],
                &mut output[..room],
                flate2::FlushDecompress::None,
            )
            .map_err(|error| {
                malformed(format!("entry {name}: invalid deflate stream ({error})"))
            })?;
        let consumed = decompressor.total_in() as usize - before_in;
        let produced = decompressor.total_out() as usize - sink.produced() as usize;
        sink.push(&output[..produced], control)?;
        checkpoints.tick(control, produced)?;
        match status {
            flate2::Status::StreamEnd => {
                let consumed_total = decompressor.total_in() as usize;
                if consumed_total != compressed.len() {
                    return Err(malformed(format!(
                        "entry {name}: {} compressed bytes follow the end of the deflate \
                         stream (trailing stream)",
                        compressed.len() - consumed_total
                    )));
                }
                break;
            }
            _ => {
                if consumed == 0 && produced == 0 {
                    if decompressor.total_in() as usize == compressed.len() {
                        return Err(malformed(format!(
                            "entry {name}: deflate stream ended after {} of {} declared \
                            bytes (truncated)",
                            sink.produced(),
                            declared
                        )));
                    }
                    return Err(malformed(format!(
                        "entry {name}: deflate stream made no progress at input offset {}",
                        decompressor.total_in()
                    )));
                }
            }
        }
    }
    if sink.produced() as usize != declared {
        return Err(malformed(format!(
            "entry {name}: decoded {} bytes, the central directory declares {declared}",
            sink.produced()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Root DEX discovery (IN-01, low-level half)
// ---------------------------------------------------------------------------

/// Root-selection result: the surviving entries in central-directory order,
/// the duplicate names inside the candidate set, and whether the fallback
/// tier was used. Deduplication keeps the *first* record per name (the
/// reference behavior); the dropped copies stay visible through `duplicates`.
#[derive(Debug)]
pub(crate) struct RootSelection<'a> {
    pub(crate) selected: Vec<&'a ArchiveEntry>,
    pub(crate) duplicates: Vec<DuplicateName>,
    /// Contract-test surface: whether the fallback tier produced the
    /// selection (asserted by the input contract suite).
    #[allow(dead_code)]
    pub(crate) used_fallback: bool,
}

impl RootSelection<'_> {
    /// The error dex-backed operations report for DEX-less archives; A07 maps
    /// classes/references/getclass onto this contract. Contract-test surface.
    #[allow(dead_code)]
    pub(crate) fn require_selected(&self) -> Result<&[&ArchiveEntry], Error> {
        if self.selected.is_empty() {
            return Err(Error::new(ErrorKind::NotFound)
                .with_context("the archive contains no root DEX entry to analyse"));
        }
        Ok(&self.selected)
    }
}

fn is_root(name: &[u8]) -> bool {
    !name.contains(&b'/')
}

fn is_classes_dex(name: &[u8]) -> bool {
    is_root(name) && name.starts_with(b"classes") && name.ends_with(b".dex")
}

fn is_any_dex(name: &[u8]) -> bool {
    is_root(name) && name.ends_with(b".dex")
}

/// Root `classes*.dex` first, any root `*.dex` as fallback; nested names
/// (containing `/`) never match. Matching is on raw bytes only. The fallback
/// tier counts as *used* only when it actually produced the selection — an
/// archive without any DEX entry reports neither a selection nor a fallback.
pub(crate) fn select_root_dexes(catalog: &ArchiveCatalog) -> RootSelection<'_> {
    let named: Vec<&ArchiveEntry> = catalog
        .entries
        .iter()
        .filter(|entry| is_classes_dex(&entry.raw_name))
        .collect();
    let any_dex: Vec<&ArchiveEntry> = catalog
        .entries
        .iter()
        .filter(|entry| is_any_dex(&entry.raw_name))
        .collect();
    let (candidates, used_fallback): (Vec<&ArchiveEntry>, bool) = if named.is_empty() {
        let used = !any_dex.is_empty();
        (any_dex, used)
    } else {
        (named, false)
    };
    let mut seen: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    let mut selected = Vec::new();
    let mut counts: BTreeMap<Vec<u8>, Vec<u32>> = BTreeMap::new();
    for entry in &candidates {
        counts
            .entry(entry.raw_name.clone())
            .or_default()
            .push(entry.ordinal);
        if seen.insert(entry.raw_name.clone()) {
            selected.push(*entry);
        }
    }
    let duplicates = counts
        .into_iter()
        .filter(|(_, ordinals)| ordinals.len() > 1)
        .map(|(name, ordinals)| DuplicateName { name, ordinals })
        .collect();
    RootSelection {
        selected,
        duplicates,
        used_fallback,
    }
}

// ---------------------------------------------------------------------------
// Test builders
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Raw deflate of `payload`, the way a ZIP writer stores a DEX entry.
    fn deflate(payload: &[u8]) -> Vec<u8> {
        let mut compressor = libdeflater::Compressor::new(libdeflater::CompressionLvl::default());
        let mut out = vec![0u8; compressor.deflate_compress_bound(payload.len())];
        let written = compressor.deflate_compress(payload, &mut out).unwrap();
        out.truncate(written);
        out
    }

    /// Builds a ZIP archive in memory. The third tuple field selects deflate
    /// (8) over stored (0); local and central headers carry the real CRC-32
    /// because the reader validates both the stream and header contract.
    pub(crate) fn build_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut local = Vec::new();
        let mut central = Vec::new();
        for (name, payload, deflated) in entries {
            let stored = if *deflated {
                deflate(payload)
            } else {
                payload.to_vec()
            };
            // PATCHED (asc, A07): the A02 reader verifies CRC-32 and the
            // local-header consistency, so the builder writes real values
            // instead of zeros.
            let crc = crate::zip::crc32(payload);
            let offset = local.len() as u32;
            local.extend_from_slice(b"PK\x03\x04");
            local.extend_from_slice(&20u16.to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(&if *deflated { 8u16 } else { 0u16 }.to_le_bytes());
            local.extend_from_slice(&[0; 4]);
            local.extend_from_slice(&crc.to_le_bytes());
            local.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            local.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            local.extend_from_slice(&(name.len() as u16).to_le_bytes());
            local.extend_from_slice(&0u16.to_le_bytes());
            local.extend_from_slice(name.as_bytes());
            local.extend_from_slice(&stored);

            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&if *deflated { 8u16 } else { 0u16 }.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let mut data = local;
        let central_offset = data.len() as u32;
        let central_size = central.len() as u32;
        data.extend_from_slice(&central);
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&central_size.to_le_bytes());
        data.extend_from_slice(&central_offset.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data
    }

    /// Writes `data` to a uniquely named temporary file.
    pub(crate) fn temp_apk(tag: &str, data: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rasc-{tag}-{}.apk", std::process::id()));
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn catalog_entry_cap_is_enforced_inside_the_walk() {
        // An EOCD that undercounts its entries must not let the walk collect
        // an unbounded directory before the count cross-check runs.
        let mut zip = build_zip(&[
            ("classes.dex", b"payload", false),
            ("classes2.dex", b"payload", false),
            ("classes3.dex", b"payload", false),
        ]);
        let eocd = zip
            .windows(4)
            .rposition(|window| window == b"PK\x05\x06")
            .expect("archive has an EOCD");
        // Declared count 1 (under the cap) while the directory holds 3.
        zip[eocd + 8..eocd + 10].copy_from_slice(&1u16.to_le_bytes());
        zip[eocd + 10..eocd + 12].copy_from_slice(&1u16.to_le_bytes());
        let limits = InputLimits {
            max_archive_entries: 2,
            ..InputLimits::DEFAULT
        };
        let error = parse_catalog(&zip, &limits).unwrap_err();
        assert!(
            error.to_string().contains("more than 2 entries"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn display_name_escapes_control_characters() {
        // A raw ESC inside a valid-UTF-8 name must not reach stderr verbatim.
        let shown = display_name(b"ok\x1b[2Jevil");
        assert!(shown.contains("\\u{1b}"), "escaped form: {shown:?}");
        assert!(
            !shown.contains('\u{1b}'),
            "raw control byte leaked: {shown:?}"
        );
    }

    #[test]
    fn read_entry_reserves_the_budget_and_rolls_back_on_failure() {
        let payload = b"budgeted payload".to_vec();
        let mut zip = build_zip(&[("classes.dex", &payload, false)]);
        let limits = InputLimits::DEFAULT;
        let catalog = parse_catalog(&zip, &limits).unwrap();
        let entry = &catalog.entries[0];
        let decoded = AtomicU64::new(0);
        let probe = ControlProbe::never();

        // Success: the reservation equals the produced bytes exactly.
        let output = read_entry(&zip, entry, &limits, &decoded, &probe).unwrap();
        assert_eq!(output, payload);
        assert_eq!(decoded.load(Ordering::Relaxed), payload.len() as u64);

        // Failure after the reservation (CRC tampered): the account rolls back.
        let start = zip
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("archive has a central directory");
        write_u32(&mut zip, start + 16, 0xDEAD_BEEF);
        let catalog = parse_catalog(&zip, &limits).unwrap();
        let entry = &catalog.entries[0];
        let error = read_entry(&zip, entry, &limits, &decoded, &probe).unwrap_err();
        assert!(
            error.to_string().contains("CRC-32 mismatch"),
            "unexpected error: {error}"
        );
        assert_eq!(
            decoded.load(Ordering::Relaxed),
            payload.len() as u64,
            "a failed read must return its reservation"
        );

        // Over-cap declaration: rejected before any decode work.
        let tight = build_zip(&[("classes.dex", &payload, false)]);
        let tight_limits = InputLimits {
            max_total_decoded_bytes: 4,
            ..InputLimits::DEFAULT
        };
        let catalog = parse_catalog(&tight, &tight_limits).unwrap();
        let entry = &catalog.entries[0];
        let error = read_entry(&tight, entry, &tight_limits, &decoded, &probe).unwrap_err();
        assert!(
            error.to_string().contains("per-operation limit"),
            "unexpected error: {error}"
        );
        assert_eq!(
            decoded.load(Ordering::Relaxed),
            payload.len() as u64,
            "an over-cap read must not touch the account"
        );
    }
}
