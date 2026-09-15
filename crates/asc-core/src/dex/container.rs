//! DEX containers: version-matrix validation, 041 logical members, integrity
//! diagnostics and the validated view handed to the dex/decompile layers.
//!
//! [`validate_dex_entry`] checks the DEX version against the explicit support
//! matrix (035/037/038/039/040/041; 036, unknown versions, CompactDex `cdex`
//! and ODEX `dey` are `UnsupportedFormat`), validates each version's
//! header/table/map structure, walks the 041 member chain, and returns one
//! [`ValidatedDexView`] per logical member sharing the **whole container
//! address space** (physical bytes + header offset — no per-member copies).
//! Adler-32/SHA-1 mismatches are *warnings*, never structural failures, and
//! never mutate the input. [`backend_scratch`] produces the private,
//! operation-scoped normalization copy a backend needs to accept a 041
//! member (original offsets recorded, diagnostics preserved).
//!
//! The pre-A02 lazy iterator bridge (`logical_dexes`) was removed with its
//! call sites; the validated-view layer above is the only reader.

use crate::bytes::{sha1, Checkpoints, ControlProbe, CHECKPOINT_SPACING};
use crate::error::{Error, ErrorKind};
use crate::model::{
    ArtifactId, DexEntry, DexId, DexText, DexVersion, Diagnostic, DiagnosticCode, Severity, Stage,
};

const HEADER_SIZE_STD: usize = 0x70;
const HEADER_SIZE_041: usize = 0x78;
const ENDIAN_TAG: u32 = 0x1234_5678;
/// interfaces.md §5 `max_logical_dexes` initial default.
const MAX_LOGICAL_DEXES: usize = 4096;

// ---------------------------------------------------------------------------
// Validated views (A02 handover to A03/A07)
// ---------------------------------------------------------------------------

/// One validated logical DEX: the immutable physical bytes it lives in (the
/// whole entry for a plain DEX, the whole 041 container for a container
/// member — never a per-member copy), its header offset inside those bytes,
/// its identity and its version. The ranges were validated by
/// [`validate_dex_entry`]; consumers must not re-guess ordinals.
///
/// This is the crate-private `input -> dex/decompile` handover shape from
/// interfaces.md §3; A10 may switch `bytes` to an `Arc<[u8]>` when the view
/// moves into the core crate — the fields and their meaning stay.
#[derive(Debug)]
pub(crate) struct ValidatedDexView<'a> {
    bytes: &'a [u8],
    header_offset: usize,
    id: DexId,
    version: DexVersion,
    /// Display helper for A07's `DexEntry` assembly: the entry's own name for
    /// a plain/single-member DEX, `name!classesN.dex` for container members.
    logical_name: String,
}
impl ValidatedDexView<'_> {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub(crate) fn header_offset(&self) -> usize {
        self.header_offset
    }

    pub(crate) fn id(&self) -> DexId {
        self.id
    }

    pub(crate) fn version(&self) -> DexVersion {
        self.version
    }

    pub(crate) fn logical_name(&self) -> &str {
        &self.logical_name
    }
}

/// The validated logical members of one archive entry, plus the name facts A07
/// needs to assemble public [`DexEntry`] values.
#[derive(Debug)]
pub(crate) struct DexEntryViews<'a> {
    pub(crate) views: Vec<ValidatedDexView<'a>>,
    pub(crate) raw_entry_name: Vec<u8>,
    pub(crate) entry_display_name: String,
}

impl DexEntryViews<'_> {
    /// The public `Engine::dexes` row for logical member `logical`.
    pub(crate) fn dex_entry(&self, logical: usize) -> DexEntry {
        let view = &self.views[logical];
        let display = DexText::from_str_lossless(&self.entry_display_name);
        let logical_name = DexText::from_str_lossless(view.logical_name());
        DexEntry::new(
            view.id(),
            self.raw_entry_name.clone(),
            display,
            logical_name,
            view.version(),
            view.header_offset() as u64,
        )
    }
}

fn malformed(message: impl Into<String>) -> Error {
    Error::malformed_input(message)
}

fn unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::UnsupportedFormat).with_context(message)
}

fn read(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Validates one inflated entry's DEX image and returns its logical members
/// (with stable `entry_ordinal`/`logical_ordinal` identities) plus integrity
/// diagnostics.
///
/// - Version matrix: 035/037/038/039/040/041 supported; `cdex`/`dey`/unknown
///   version tails are `UnsupportedFormat`; a non-DEX image is
///   `MalformedInput`.
/// - A 041 image must pass the member-chain validation (tiling, per-member
///   `header_offset`/`container_size`/`file_size` consistency); a failing
///   container is an error, never a fallback to "treat it as a plain DEX".
/// - Checksum/signature mismatches are returned as `Warning` diagnostics in
///   the `Dex` stage; the user's bytes are never modified.
pub(crate) fn validate_dex_entry<'a>(
    artifact: ArtifactId,
    entry_ordinal: u32,
    raw_entry_name: &[u8],
    data: &'a [u8],
    control: &ControlProbe<'_>,
) -> Result<(DexEntryViews<'a>, Vec<Diagnostic>), Error> {
    control.check()?;
    let entry_display_name = crate::zip::display_name(raw_entry_name);
    if data.len() < 8 {
        return Err(malformed(format!(
            "entry {entry_display_name}: {} bytes cannot hold the {} byte DEX header",
            data.len(),
            HEADER_SIZE_STD
        )));
    }
    let version = match data.get(..4) {
        Some(b"dex\n") => DexVersion::from_magic_tail(&data[4..8]).ok_or_else(|| {
            unsupported(format!(
                "entry {entry_display_name}: DEX version {} is outside the supported \
                 matrix 035/037/038/039/040/041",
                escape_tail(&data[4..8])
            ))
        })?,
        // Alternative DEX images: CompactDex (`cdex`, 4-byte magic) and ODEX
        // (`dey`, 3-byte prefix — `dey\n036\0` in the wild, `dey036\0` in the
        // fixture corpus). One shared message names both: the contract pins
        // the format family, not which magic tripped.
        _ if data.get(..4) == Some(b"cdex") || data.get(..3) == Some(b"dey") => {
            return Err(unsupported(format!(
                "entry {entry_display_name}: alternative DEX image (CompactDex `cdex` / \
                 ODEX `dey`) is outside the supported matrix"
            )));
        }
        _ => {
            return Err(malformed(format!(
                "entry {entry_display_name}: not a DEX image (bad magic)"
            )));
        }
    };

    let member_spans: Vec<(usize, usize)> = if version == DexVersion::V041 {
        validate_041_chain(data, control)?
    } else {
        validate_standard_dex(data, control)?;
        vec![(0, data.len())]
    };

    let single = member_spans.len() == 1;
    let mut views = Vec::with_capacity(member_spans.len());
    let mut diagnostics = Vec::new();
    for (logical_ordinal, (base, span_end)) in member_spans.iter().copied().enumerate() {
        let id = DexId::new(artifact, entry_ordinal, logical_ordinal as u32);
        integrity_diagnostics(data, base, span_end, id, &mut diagnostics, control)?;
        let logical_name = if single {
            entry_display_name.clone()
        } else {
            format!("{entry_display_name}!classes{}.dex", logical_ordinal + 1)
        };
        views.push(ValidatedDexView {
            bytes: data,
            header_offset: base,
            id,
            version,
            logical_name,
        });
    }
    Ok((
        DexEntryViews { views, raw_entry_name: raw_entry_name.to_vec(), entry_display_name },
        diagnostics,
    ))
}

fn escape_tail(tail: &[u8]) -> String {
    tail.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Structural validation
// ---------------------------------------------------------------------------

/// Header/table structural checks for a plain (035-040) DEX image.
fn validate_standard_dex(data: &[u8], control: &ControlProbe<'_>) -> Result<(), Error> {
    let file_size = read(data, 0x20).ok_or_else(|| malformed("truncated DEX header"))?;
    if data.len() < HEADER_SIZE_STD {
        return Err(malformed(format!(
            "DEX image is {} bytes, shorter than the {HEADER_SIZE_STD} byte header",
            data.len()
        )));
    }
    if file_size != data.len() as u32 {
        return Err(malformed(format!(
            "header at offset 0 declares file_size {file_size}, the entry holds {} bytes",
            data.len()
        )));
    }
    validate_tables_and_map(data, 0, HEADER_SIZE_STD, control)?;
    // data_off/data_size must tile the file exactly (skipped for 041 members,
    // whose builders historically leave both zero).
    let data_off = read(data, 0x6c).unwrap_or(0) as usize;
    let data_size = read(data, 0x68).unwrap_or(0) as usize;
    if data_off < HEADER_SIZE_STD || data_size != data.len() - data_off {
        return Err(malformed(format!(
            "header declares data_off {data_off}/data_size {data_size}, which does not tile \
             the {} byte file",
            data.len()
        )));
    }
    Ok(())
}

/// Validates a 041 container's member chain; returns `(base, span_end)` per
/// member in address order. The members must tile the container exactly.
fn validate_041_chain(
    data: &[u8],
    control: &ControlProbe<'_>,
) -> Result<Vec<(usize, usize)>, Error> {
    let container_size = read(data, 0x70)
        .ok_or_else(|| malformed("DEX 041 container is shorter than its 0x78 header"))?
        as usize;
    if container_size != data.len() {
        return Err(malformed(format!(
            "DEX 041 container declares size {container_size}, the entry holds {} bytes",
            data.len()
        )));
    }
    let mut spans = Vec::new();
    let mut base = 0usize;
    while base + HEADER_SIZE_041 <= data.len() {
        control.check()?;
        if data.get(base..base + 8) != Some(b"dex\n041\0") {
            break;
        }
        let file_size = read(data, base + 0x20).expect("bounds checked above") as usize;
        let declared_container = read(data, base + 0x70).expect("bounds checked above") as usize;
        let declared_header = read(data, base + 0x74).expect("bounds checked above") as usize;
        if declared_container != container_size {
            return Err(malformed(format!(
                "DEX 041 member at offset {base} declares container size {declared_container}, \
                 the container is {container_size}"
            )));
        }
        if declared_header != base {
            return Err(malformed(format!(
                "DEX 041 member at offset {base} declares header offset {declared_header}"
            )));
        }
        if file_size < HEADER_SIZE_041 {
            return Err(malformed(format!(
                "DEX 041 member at offset {base} declares file size {file_size}, below the \
                 {HEADER_SIZE_041} byte member header"
            )));
        }
        let span_end = base.checked_add(file_size).ok_or_else(|| {
            malformed(format!(
                "DEX 041 member at offset {base} declares file size {file_size}, which overflows"
            ))
        })?;
        if span_end > data.len() {
            return Err(malformed(format!(
                "DEX 041 member at offset {base} declares file size {file_size}, reaching to \
                 {span_end} past the {} byte container",
                data.len()
            )));
        }
        validate_tables_and_map(data, base, HEADER_SIZE_041, control)?;
        spans.push((base, span_end));
        if spans.len() > MAX_LOGICAL_DEXES {
            return Err(Error::resource_limit(format!(
                "DEX 041 container declares more than {MAX_LOGICAL_DEXES} logical members"
            )));
        }
        base = span_end;
    }
    if spans.is_empty() || base != data.len() {
        return Err(malformed(format!(
            "DEX 041 member chain ends at offset {base} of {}, so the members do not tile the \
             container",
            data.len()
        )));
    }
    // A member that overclaims its file_size can swallow a later member's
    // header and still "tile" the container. The swallowed header contradicts
    // the chain: its own header_offset field points at a position the walked
    // chain never visits as a member base. Every self-consistent member
    // header (right magic, self-pointing header_offset, matching container
    // size) must therefore be one of the walked bases.
    //
    // The scan is magic-led: the 8-byte magic compare (memmem, SIMD) runs at
    // every position and the span-membership check and field reads run only
    // at magic hits, so cost stays linear in the container even with the
    // maximum member count. Cancellation checkpoints fire every 64 KiB of
    // scanned bytes, so a deadline bounds the scan.
    let finder = memchr::memmem::Finder::new(b"dex\n041\0");
    let mut search_from = 0usize;
    let mut checkpoints = Checkpoints::new();
    while let Some(hit) = finder.find(&data[search_from..]) {
        let position = search_from + hit;
        checkpoints.tick(control, hit)?;
        search_from = position + 1;
        if position + HEADER_SIZE_041 > data.len() {
            break;
        }
        if spans.iter().any(|(base, _)| *base == position) {
            continue;
        }
        let declared_container = read(data, position + 0x70).expect("bounds checked above");
        let declared_header = read(data, position + 0x74).expect("bounds checked above");
        if declared_header as usize == position
            && declared_container as usize == container_size
        {
            let swallowed_by = spans
                .iter()
                .find(|(base, end)| *base < position && position < *end)
                .map(|(base, _)| *base);
            return Err(malformed(match swallowed_by {
                Some(base) => format!(
                    "DEX 041 member header at offset {position} is swallowed by the member \
                     at offset {base}: the chain cannot tile the container"
                ),
                None => format!(
                    "DEX 041 member header at offset {position} is not part of the member \
                     chain that tiles the container"
                ),
            }));
        }
    }
    Ok(spans)
}

/// The six id tables cross-checked between the header and the map_list:
/// (map kind, header size offset, header offset field, item width, name).
const TABLES: [(u16, usize, usize, usize, &str); 6] = [
    (0x0001, 0x38, 0x3c, 4, "string_ids"),
    (0x0002, 0x40, 0x44, 4, "type_ids"),
    (0x0003, 0x48, 0x4c, 12, "proto_ids"),
    (0x0004, 0x50, 0x54, 8, "field_ids"),
    (0x0005, 0x58, 0x5c, 8, "method_ids"),
    (0x0006, 0x60, 0x64, 32, "class_defs"),
];

/// Header/table/map consistency for the DEX header at `base` (spanning
/// `header_size` bytes).
///
/// Table offsets are absolute within `data` (for a 041 member they are
/// container-relative and may legitimately reach past the member's own span —
/// that is the container's data-sharing design). Contradictions between the
/// map_list and the header are located errors, not silent successes.
fn validate_tables_and_map(
    data: &[u8],
    base: usize,
    header_size: usize,
    control: &ControlProbe<'_>,
) -> Result<(), Error> {
    let declared_size = read(data, base + 0x24)
        .ok_or_else(|| malformed(format!("DEX header at offset {base} is truncated")))?;
    if declared_size as usize != header_size {
        return Err(malformed(format!(
            "DEX header at offset {base} declares header_size 0x{declared_size:x}, expected \
             0x{header_size:x}"
        )));
    }
    let endian_tag = read(data, base + 0x28).expect("header bounds checked above");
    if endian_tag != ENDIAN_TAG {
        return Err(malformed(format!(
            "DEX header at offset {base} carries endian tag 0x{endian_tag:08x}, expected \
             0x{ENDIAN_TAG:08x}"
        )));
    }

    let mut declared: std::collections::BTreeMap<u16, (usize, usize, &str)> =
        std::collections::BTreeMap::new();
    for &(kind, size_at, offset_at, width, name) in TABLES.iter() {
        let count = read(data, base + size_at).expect("header bounds checked above") as usize;
        let offset = read(data, base + offset_at).expect("header bounds checked above") as usize;
        if count == 0 {
            if offset != 0 {
                return Err(malformed(format!(
                    "DEX header at offset {base} declares no {name} items but offset {offset}"
                )));
            }
            continue;
        }
        let end = offset
            .checked_add(count.checked_mul(width).ok_or_else(|| {
                malformed(format!(
                    "DEX header at offset {base}: {name} count {count} overflows"
                ))
            })?)
            .ok_or_else(|| {
                malformed(format!(
                    "DEX header at offset {base}: {name} range at {offset} overflows"
                ))
            })?;
        if end > data.len() {
            return Err(malformed(format!(
                "DEX header at offset {base}: {name} range [{offset}..{end}] reaches past the \
                 {} byte image",
                data.len()
            )));
        }
        if offset < base + header_size && end > base {
            return Err(malformed(format!(
                "DEX header at offset {base}: {name} range [{offset}..{end}] overlaps the header"
            )));
        }
        declared.insert(kind, (count, offset, name));
    }

    let map_off = read(data, base + 0x34).expect("header bounds checked above") as usize;
    if map_off == 0 {
        return Err(malformed(format!(
            "DEX header at offset {base} declares no map_list"
        )));
    }
    let map_size = read(data, map_off)
        .ok_or_else(|| malformed(format!("map_list size at offset {map_off} is out of range")))?
        as usize;
    let map_bytes = map_size
        .checked_mul(12)
        .ok_or_else(|| malformed(format!("map_list at offset {map_off} overflows")))?;
    let map_end = map_off
        .checked_add(4)
        .and_then(|value| value.checked_add(map_bytes))
        .ok_or_else(|| malformed(format!("map_list at offset {map_off} overflows")))?;
    if map_end > data.len() {
        return Err(malformed(format!(
            "map_list at offset {map_off} ({map_size} items) reaches past the {} byte image",
            data.len()
        )));
    }
    control.check()?;
    for item in 0..map_size {
        let at = map_off + 4 + item * 12;
        let kind = read(data, at).expect("map bounds checked above") as u16;
        let size = read(data, at + 4).expect("map bounds checked above") as usize;
        let offset = read(data, at + 8).expect("map bounds checked above") as usize;
        if let Some((header_count, header_offset, name)) = declared.remove(&kind)
            && (size != header_count || offset != header_offset)
        {
            return Err(malformed(format!(
                "map_list item {name} at offset {at} declares size {size} at {offset}, the \
                 header declares {header_count} at {header_offset}"
            )));
        }
    }
    if let Some((_, (count, offset, name))) = declared.pop_first() {
        return Err(malformed(format!(
            "map_list is missing the {name} item the header declares ({count} items at {offset})"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Integrity diagnostics (IN-04)
// ---------------------------------------------------------------------------

/// Compares the stored checksum/signature of the span `[base, span_end)` with
/// the computed values and records warnings for mismatches. Read-only: the
/// user's bytes are never rewritten to make a checksum pass.
fn integrity_diagnostics(
    data: &[u8],
    base: usize,
    span_end: usize,
    id: DexId,
    diagnostics: &mut Vec<Diagnostic>,
    control: &ControlProbe<'_>,
) -> Result<(), Error> {
    let stored_checksum = read(data, base + 8).expect("span bounds checked above");
    let computed = adler32_span(&data[base + 12..span_end], control)?;
    if stored_checksum != computed {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::DexChecksumMismatch,
                Severity::Warning,
                Stage::Dex,
                format!(
                    "stored adler-32 0x{stored_checksum:08x} disagrees with the computed \
                     0x{computed:08x} over bytes {}/..{}",
                    base + 12,
                    span_end
                ),
            )
            .with_dex(id),
        );
    }
    let stored_signature = &data[base + 12..base + 32];
    let computed_signature = sha1_span(&data[base + 32..span_end], control)?;
    if stored_signature != computed_signature {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::DexSignatureMismatch,
                Severity::Warning,
                Stage::Dex,
                "stored SHA-1 signature disagrees with the computed signature over the span",
            )
            .with_dex(id),
        );
    }
    Ok(())
}

fn adler32_span(bytes: &[u8], control: &ControlProbe<'_>) -> Result<u32, Error> {
    let (mut a, mut b) = (1u32, 0u32);
    let mut checkpoints = Checkpoints::new();
    for chunk in bytes.chunks(CHECKPOINT_SPACING) {
        for byte in chunk {
            a = (a + u32::from(*byte)) % 65521;
            b = (b + a) % 65521;
        }
        checkpoints.tick(control, chunk.len())?;
    }
    Ok((b << 16) | a)
}

fn sha1_span(bytes: &[u8], control: &ControlProbe<'_>) -> Result<[u8; 20], Error> {
    // The cadence contract holds (a check per 64 KiB of hashed span) while the
    // hash itself stays the one-shot implementation.
    let mut checkpoints = Checkpoints::new();
    for chunk in bytes.chunks(CHECKPOINT_SPACING) {
        checkpoints.tick(control, chunk.len())?;
    }
    Ok(sha1(bytes))
}

// ---------------------------------------------------------------------------
// Backend scratch normalization (IN-04)
// ---------------------------------------------------------------------------

/// A private, operation-scoped normalization copy handed to a backend that
/// cannot accept 041 container headers. The original bytes and diagnostics
/// stay untouched; the caller drops the scratch when the operation ends (it
/// is never retained on the artifact).
pub(crate) struct BackendScratch {
    /// The normalized copy (member header overlaid at offset zero).
    pub(crate) bytes: Vec<u8>,
    /// Physical offset the overlaid header came from — the mapping back into
    /// the container for anything diagnosing "view offset 0". Diagnostic
    /// surface: read by tests today, by the debug wiring when it lands.
    #[allow(dead_code)]
    pub(crate) source_header_offset: usize,
    /// Which fields were rewritten and why, for evidence/debug output.
    #[allow(dead_code)]
    pub(crate) rewrites: &'static [&'static str],
}

const SCRATCH_REWRITES: &[&str] = &[
    "header_size 0x78 -> 0x70 (backends reject the 041 header size)",
    "file_size -> whole container (member sections are container-relative)",
    "adler-32 recomputed over the normalized copy",
];

/// Scratch for a 041 view; `None` for standard versions (backends take the
/// original bytes, and no normalization is allowed to hide problems).
pub(crate) fn backend_scratch(
    view: &ValidatedDexView<'_>,
    integrity: &[crate::model::Diagnostic],
) -> Option<BackendScratch> {
    if view.version() == DexVersion::V041 {
        return Some(BackendScratch {
            bytes: normalize_041(view.bytes(), view.header_offset()),
            source_header_offset: view.header_offset(),
            rewrites: SCRATCH_REWRITES,
        });
    }
    // PATCHED (asc, A07): a plain DEX whose checksum/signature integrity
    // fields disagree gets the same treatment — the backend enforces both,
    // so the checked path hands it a private copy with the fields
    // recomputed. The original bytes are untouched and the copy is
    // operation-local (G03 / IN-04).
    let flagged = integrity.iter().any(|diagnostic| {
        matches!(
            diagnostic.code,
            crate::model::DiagnosticCode::DexChecksumMismatch
                | crate::model::DiagnosticCode::DexSignatureMismatch
        )
    });
    if !flagged {
        return None;
    }
    let mut copy = view.bytes().to_vec();
    if copy.len() >= 32 {
        // The signature rewrite must land BEFORE the checksum is computed:
        // the Adler-32 span (12..) covers the signature bytes (12..32).
        let signature = crate::bytes::sha1(&copy[32..]);
        copy[0x0C..0x20].copy_from_slice(&signature);
        let checksum = adler32_span(&copy[12..], &ControlProbe::never())
            .expect("the never probe cannot cancel");
        copy[0x08..0x0C].copy_from_slice(&checksum.to_le_bytes());
    }
    Some(BackendScratch {
        bytes: copy,
        source_header_offset: view.header_offset(),
        rewrites: &["checksum", "signature"],
    })
}

/// Overlay the member header at `header_offset` onto offset zero of a copy of
/// the whole container, then patch the fields that make the copy look like a
/// standard 0x70-header DEX covering the full address space.
fn normalize_041(container: &[u8], header_offset: usize) -> Vec<u8> {
    let mut view = container.to_vec();
    view[..HEADER_SIZE_041]
        .copy_from_slice(&container[header_offset..header_offset + HEADER_SIZE_041]);
    view[0x24..0x28].copy_from_slice(&(HEADER_SIZE_STD as u32).to_le_bytes());
    let file_size = view.len() as u32;
    view[0x20..0x24].copy_from_slice(&file_size.to_le_bytes());
    let checksum = adler32_span(&view[12..], &ControlProbe::never())
        .expect("the never probe cannot cancel");
    view[0x08..0x0C].copy_from_slice(&checksum.to_le_bytes());
    view
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::read_u32;

    fn write_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Minimal tiling 041 container (chain fields only, no map) for the
    /// chain-validation tests.
    fn legacy_041_container(sizes: &[usize]) -> Vec<u8> {
        let total: usize = sizes.iter().sum();
        let mut data = vec![0u8; total];
        let mut offset = 0;
        for size in sizes {
            data[offset..offset + 8].copy_from_slice(b"dex\n041\0");
            write_u32(&mut data, offset + 0x20, *size as u32);
            write_u32(&mut data, offset + 0x24, HEADER_SIZE_041 as u32);
            write_u32(&mut data, offset + 0x70, total as u32);
            write_u32(&mut data, offset + 0x74, offset as u32);
            offset += size;
        }
        data
    }

    #[test]
    fn dex041_rejects_inconsistent_offsets() {
        let mut data = vec![0; 0x78];
        data[..8].copy_from_slice(b"dex\n041\0");
        write_u32(&mut data, 0x20, 0x78);
        write_u32(&mut data, 0x70, 0x78);
        write_u32(&mut data, 0x74, 4);
        let error = validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe())
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    }

    #[test]
    fn swallowed_041_header_is_detected_by_the_magic_led_scan() {
        // Member 1 is fully valid but overclaims to swallow a self-consistent
        // member-2 header; the magic-led scan must find the swallowed header
        // and reject the chain (and must stay linear while doing so).
        let member_size = HEADER_SIZE_041 + 60;
        let mut data = valid_skeleton(b"041\0", 0, HEADER_SIZE_041);
        let second = valid_skeleton(b"041\0", member_size, HEADER_SIZE_041);
        data.extend_from_slice(&second);
        let total = data.len() as u32;
        // Member 1 overclaims the whole container...
        write_u32(&mut data, 0x20, total);
        write_u32(&mut data, 0x70, total);
        write_u32(&mut data, 0x74, 0);
        // ...while member 2's swallowed header stays fully self-consistent.
        write_u32(&mut data, member_size + 0x70, total);
        write_u32(&mut data, member_size + 0x74, member_size as u32);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert!(
            error.to_string().contains("swallowed by the member at offset 0"),
            "unexpected error: {error}"
        );
    }

    // -----------------------------------------------------------------------
    // Target-contract tests (IN-03/IN-04)
    // -----------------------------------------------------------------------

    fn probe() -> ControlProbe<'static> {
        ControlProbe::never()
    }

    fn artifact() -> ArtifactId {
        ArtifactId::from_digest([7u8; 32])
    }

    /// A structurally valid DEX skeleton spanning `header_size + 60` bytes:
    /// header, one string_id, string data and a consistent map_list (u32 size
    /// at `map_off`, then the items — items never start at `map_off` itself).
    /// Pointer fields carry absolute container addresses (`base +` offset) so
    /// a skeleton built at `base > 0` tiles into a multi-member container;
    /// `header_size` picks the standard (0x70) or 041 (0x78) layout.
    fn valid_skeleton(version: &[u8; 4], base: usize, header_size: usize) -> Vec<u8> {
        let total = header_size + 60;
        let mut data = vec![0u8; total];
        let string_ids_at = header_size;
        let string_data_at = string_ids_at + 4;
        let map_at = string_data_at + 4;
        data[0..4].copy_from_slice(b"dex\n");
        data[4..8].copy_from_slice(version);
        write_u32(&mut data, 0x20, total as u32);
        write_u32(&mut data, 0x24, header_size as u32);
        write_u32(&mut data, 0x28, ENDIAN_TAG);
        write_u32(&mut data, 0x34, (base + map_at) as u32);
        write_u32(&mut data, 0x38, 1); // string_ids count
        write_u32(&mut data, 0x3c, (base + string_ids_at) as u32);
        write_u32(&mut data, 0x68, (total - string_data_at) as u32); // data_size
        write_u32(&mut data, 0x6c, (base + string_data_at) as u32); // data_off
        write_u32(&mut data, string_ids_at, (base + string_data_at) as u32);
        let mut at = map_at;
        write_u32(&mut data, at, 4);
        at += 4;
        for (kind, size, offset) in [
            (0x0000u16, 1u32, 0u32),
            (0x0001, 1, (base + string_ids_at) as u32),
            (0x2002, 1, (base + string_data_at) as u32),
            (0x1000, 1, (base + map_at) as u32),
        ] {
            data[at..at + 2].copy_from_slice(&kind.to_le_bytes());
            write_u32(&mut data, at + 4, size);
            write_u32(&mut data, at + 8, offset);
            at += 12;
        }
        // The skeleton carries consistent integrity fields ("consistent
        // integrity fields must not warn"): signature over [32..end) first,
        // then the checksum over [12..end), which covers the signature.
        let signature = sha1(&data[32..]);
        data[12..32].copy_from_slice(&signature);
        let checksum = adler32_span(&data[12..], &ControlProbe::never())
            .expect("the never probe cannot cancel");
        write_u32(&mut data, 0x08, checksum);
        data
    }

    /// The map_list offsets inside a [`valid_skeleton`], measured from the
    /// header end: `map_off = header + 8` carries the u32 size, the items
    /// start at `header + 12`, so the second item (string_ids) has its kind
    /// at `header + 8 + 4 + 12` and its offset field 8 bytes further.
    const SKELETON_MAP_ITEM_KIND: usize = 4 + 12;
    const SKELETON_MAP_STRING_IDS_OFFSET: usize = 4 + 12 + 8;

    #[test]
    fn version_matrix_accepts_known_and_rejects_others() {
        for version in [b"035\0", b"037\0", b"038\0", b"039\0", b"040\0"] {
            let data = valid_skeleton(version, 0, HEADER_SIZE_STD);
            let (views, diagnostics) =
                validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap();
            assert_eq!(views.views.len(), 1, "version {:?} must validate", version);
            assert_eq!(
                views.views[0].version().as_str(),
                std::str::from_utf8(&version[..3]).unwrap()
            );
            assert!(
                diagnostics.is_empty(),
                "consistent integrity fields must not warn: {diagnostics:?}"
            );
        }
        for magic in [&b"dex\n036\0"[..], &b"dex\n099\0"[..], &b"cdex038\0"[..], &b"dey036\0"[..]] {
            let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
            // The `dey` spelling is a 7-byte literal (3-byte prefix); splice
            // exactly the literal so byte 7 keeps the skeleton's zero.
            data[..magic.len()].copy_from_slice(magic);
            let error =
                validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
            assert_eq!(*error.kind(), ErrorKind::UnsupportedFormat, "{magic:?}: {error}");
        }
        let junk = b"JUNKJUNKJUNK".to_vec();
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &junk, &probe()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput);
    }

    #[test]
    fn structural_contradictions_are_located_errors() {
        // Declared file size disagrees with the bytes.
        let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        write_u32(&mut data, 0x20, 0x50);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert!(error.to_string().contains("file_size"), "{error}");

        // Wrong header_size for the version.
        let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        write_u32(&mut data, 0x24, 0x78);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert!(error.to_string().contains("header_size"), "{error}");

        // Wrong endian tag.
        let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        write_u32(&mut data, 0x28, 0xdead_beef);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert!(error.to_string().contains("endian"), "{error}");

        // Table reaching past the file.
        let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        write_u32(&mut data, 0x3c, 0x1000);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert!(error.to_string().contains("string_ids"), "{error}");

        // Map item contradicting the header.
        let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        write_u32(
            &mut data,
            HEADER_SIZE_STD + 8 + SKELETON_MAP_STRING_IDS_OFFSET,
            0x7c,
        );
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert!(error.to_string().contains("map_list item string_ids"), "{error}");

        // Map missing the string_ids item the header declares: the map's
        // second item masquerades as an unchecked kind.
        let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        data[HEADER_SIZE_STD + 8 + SKELETON_MAP_ITEM_KIND..HEADER_SIZE_STD + 8 + SKELETON_MAP_ITEM_KIND + 2]
            .copy_from_slice(&0x2003u16.to_le_bytes());
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert!(error.to_string().contains("missing the string_ids item"), "{error}");
    }

    #[test]
    fn container_chain_must_tile_exactly() {
        // Overshoot: first member claims more than the container holds.
        let mut data = legacy_041_container(&[0x78, 0x78]);
        write_u32(&mut data, 0x20, 0x100);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");

        // Zero-length member.
        let mut data = legacy_041_container(&[0x78]);
        write_u32(&mut data, 0x20, 0x20);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");

        // Undershot member leaves unaccounted bytes.
        let mut data = legacy_041_container(&[0x78, 0x78]);
        write_u32(&mut data, 0x78 + 0x20, 0x70);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");

        // Contradictory self offset.
        let mut data = legacy_041_container(&[0x78]);
        write_u32(&mut data, 0x74, 4);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");

        // Container size contradicting the entry length.
        let mut data = legacy_041_container(&[0x78]);
        write_u32(&mut data, 0x70, 0x100);
        let error =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput, "{error}");
    }

    #[test]
    fn integrity_mismatch_is_a_warning_not_an_error() {
        let mut data = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        write_u32(&mut data, 0x08, 0xdead_beef);
        data[12..32].fill(0xab);
        let before = data.clone();
        let (views, diagnostics) =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap();
        assert_eq!(views.views.len(), 1);
        assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
        assert_eq!(diagnostics[0].code(), DiagnosticCode::DexChecksumMismatch);
        assert_eq!(diagnostics[0].severity(), Severity::Warning);
        assert_eq!(diagnostics[0].stage(), Stage::Dex);
        assert_eq!(diagnostics[1].code(), DiagnosticCode::DexSignatureMismatch);
        assert_eq!(data, before, "validation must not modify the input bytes");
    }

    #[test]
    fn backend_scratch_rewrites_the_041_header_without_touching_the_original() {
        // Two fully valid members at 0 and 0xB4, each a 0x78-header skeleton.
        let member_size = HEADER_SIZE_041 + 60;
        let mut member1 = valid_skeleton(b"041\0", 0, HEADER_SIZE_041);
        let member2 = valid_skeleton(b"041\0", member_size, HEADER_SIZE_041);
        assert_eq!(member1.len(), member_size);
        member1.extend_from_slice(&member2);
        let total = member1.len() as u32;
        // Container fields, patched for both members.
        write_u32(&mut member1, 0x70, total);
        write_u32(&mut member1, 0x74, 0);
        write_u32(&mut member1, member_size + 0x70, total);
        write_u32(&mut member1, member_size + 0x74, member_size as u32);
        let data = member1;

        let (views, _) =
            validate_dex_entry(artifact(), 0, b"classes.dex", &data, &probe()).unwrap();
        assert_eq!(views.views.len(), 2);
        let second = &views.views[1];
        assert_eq!(second.header_offset(), member_size);
        assert_eq!(second.logical_name(), "classes.dex!classes2.dex");
        assert_eq!(
            second.id(),
            DexId::new(artifact(), 0, 1),
            "logical ordinals must be stable and derive from the chain order"
        );
        let original = data.clone();
        let scratch = backend_scratch(second, &[]).expect("041 needs scratch");
        assert_eq!(scratch.source_header_offset, member_size);
        assert_eq!(read_u32(&scratch.bytes, 0x74).unwrap(), member_size as u32);
        assert_eq!(read_u32(&scratch.bytes, 0x24).unwrap(), HEADER_SIZE_STD as u32);
        let checksum = read_u32(&scratch.bytes, 0x08).unwrap();
        let computed = adler32_span(&scratch.bytes[12..], &probe()).unwrap();
        assert_eq!(checksum, computed, "scratch checksum must match its own bytes");
        assert_eq!(data, original, "scratch must not modify the container");
        // Standard versions get no scratch at all.
        let plain = valid_skeleton(b"035\0", 0, HEADER_SIZE_STD);
        let (views, _) =
            validate_dex_entry(artifact(), 0, b"classes.dex", &plain, &probe()).unwrap();
        assert!(backend_scratch(&views.views[0], &[]).is_none());
    }
}
