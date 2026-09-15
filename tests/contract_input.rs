//! Contract tests for the A02 input layer: the low-level half of root DEX
//! discovery (IN-01), the ZIP support/integrity matrix (IN-02), the DEX
//! version and 041 container matrix (IN-03), and integrity diagnostics
//! (IN-04).
//!
//! The production sources under test are compiled in via `#[path]` includes,
//! the same approach tests/contract_query.rs uses, so this test target does
//! not depend on the binary crate's other modules. Fixture builders live here
//! (A02-owned); tests/support is consumed read-only.

#![allow(dead_code)]

mod support;

#[path = "../src/bytes.rs"]
mod bytes;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/model.rs"]
mod model;
#[path = "../src/zip.rs"]
mod zip;
#[path = "../src/dex/container.rs"]
mod container;

use bytes::ControlProbe;
use container::{backend_scratch, validate_dex_entry};
use error::{CancelCause, ErrorKind};
use model::{ArtifactId, DiagnosticCode, Severity, Stage};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use support::sha;
use zip::{display_name, parse_catalog, read_entry, select_root_dexes, InputLimits};

fn contracts_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join("contracts")
}

fn input_path(name: &str) -> PathBuf {
    contracts_dir().join("inputs").join(name)
}

fn read_input(name: &str) -> Vec<u8> {
    fs::read(input_path(name)).unwrap_or_else(|error| panic!("read input {name}: {error}"))
}

fn artifact_of(apk: &[u8]) -> ArtifactId {
    ArtifactId::from_digest(sha::sha256(apk))
}

fn never_cancel() -> ControlProbe<'static> {
    ControlProbe::never()
}

fn assert_kind(error: &error::Error, kind: &ErrorKind, needle: &str) {
    assert_eq!(error.kind(), kind, "unexpected error: {error}");
    assert!(error.to_string().contains(needle), "message lacks {needle:?}: {error}");
}

// ---------------------------------------------------------------------------
// ZIP fixture builder (contract-grade: real CRCs, optional data descriptors)
// ---------------------------------------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

fn deflate_raw(payload: &[u8]) -> Vec<u8> {
    let mut compressor = libdeflater::Compressor::new(libdeflater::CompressionLvl::default());
    let mut out = vec![0u8; compressor.deflate_compress_bound(payload.len())];
    let written = compressor.deflate_compress(payload, &mut out).unwrap();
    out.truncate(written);
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Descriptor {
    None,
    WithSignature,
    WithoutSignature,
}

#[derive(Clone, Copy)]
struct EntrySpec<'a> {
    name: &'a str,
    payload: &'a [u8],
    deflate: bool,
    descriptor: Descriptor,
}

impl<'a> EntrySpec<'a> {
    const fn stored(name: &'a str, payload: &'a [u8]) -> Self {
        EntrySpec { name, payload, deflate: false, descriptor: Descriptor::None }
    }

    const fn deflated(name: &'a str, payload: &'a [u8]) -> Self {
        EntrySpec { name, payload, deflate: true, descriptor: Descriptor::None }
    }

    const fn streamed(name: &'a str, payload: &'a [u8], deflate: bool, with_sig: bool) -> Self {
        EntrySpec {
            name,
            payload,
            deflate,
            descriptor: if with_sig {
                Descriptor::WithSignature
            } else {
                Descriptor::WithoutSignature
            },
        }
    }
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Central-directory field offsets inside a fixed-header record.
const CD_FLAGS: usize = 8;
const CD_METHOD: usize = 10;
const CD_CRC: usize = 16;
const CD_COMPRESSED: usize = 20;
const CD_UNCOMPRESSED: usize = 24;
const CD_LOCAL_OFFSET: usize = 42;
/// Local-header field offsets.
const LH_FLAGS: usize = 6;
const LH_METHOD: usize = 8;

/// Builds a well-formed single-volume ZIP with real CRC-32 values, DOS epoch
/// timestamps and optional data descriptors (with or without the signature).
/// For a single stored entry the bytes match the A00 `apk_with_single_dex`
/// writer exactly.
fn build_contract_zip(entries: &[EntrySpec<'_>]) -> Vec<u8> {
    const VERSION: u16 = 20;
    const DOS_TIME: u16 = 0;
    const DOS_DATE: u16 = 0x21;

    let mut local = Vec::new();
    let mut central = Vec::new();
    for spec in entries {
        let payload = spec.payload;
        let stored = if spec.deflate { deflate_raw(payload) } else { payload.to_vec() };
        let crc = crc32(payload);
        let method: u16 = if spec.deflate { 8 } else { 0 };
        let flags: u16 = if spec.descriptor == Descriptor::None { 0 } else { 0x0008 };
        let name = spec.name.as_bytes();
        let offset = local.len() as u32;

        local.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut local, VERSION);
        push_u16(&mut local, flags);
        push_u16(&mut local, method);
        push_u16(&mut local, DOS_TIME);
        push_u16(&mut local, DOS_DATE);
        match spec.descriptor {
            Descriptor::None => {
                push_u32(&mut local, crc);
                push_u32(&mut local, stored.len() as u32);
                push_u32(&mut local, payload.len() as u32);
            }
            _ => {
                push_u32(&mut local, 0);
                push_u32(&mut local, 0);
                push_u32(&mut local, 0);
            }
        }
        push_u16(&mut local, name.len() as u16);
        push_u16(&mut local, 0);
        local.extend_from_slice(name);
        local.extend_from_slice(&stored);
        if spec.descriptor != Descriptor::None {
            if spec.descriptor == Descriptor::WithSignature {
                push_u32(&mut local, 0x0807_4B50);
            }
            push_u32(&mut local, crc);
            push_u32(&mut local, stored.len() as u32);
            push_u32(&mut local, payload.len() as u32);
        }

        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, VERSION);
        push_u16(&mut central, VERSION);
        push_u16(&mut central, flags);
        push_u16(&mut central, method);
        push_u16(&mut central, DOS_TIME);
        push_u16(&mut central, DOS_DATE);
        push_u32(&mut central, crc);
        push_u32(&mut central, stored.len() as u32);
        push_u32(&mut central, payload.len() as u32);
        push_u16(&mut central, name.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, offset);
        central.extend_from_slice(name);
    }
    let mut out = local;
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, entries.len() as u16);
    push_u16(&mut out, entries.len() as u16);
    push_u32(&mut out, cd_size);
    push_u32(&mut out, cd_offset);
    push_u16(&mut out, 0);
    out
}

fn find_eocd(data: &[u8]) -> usize {
    data.windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("fixture has an EOCD")
}

/// Position of the central-directory record #`ordinal`.
fn cd_record(data: &[u8], ordinal: usize) -> usize {
    let eocd = find_eocd(data);
    let cd_offset =
        u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let mut at = cd_offset;
    for _ in 0..ordinal {
        let name_len = u16::from_le_bytes(data[at + 28..at + 30].try_into().unwrap()) as usize;
        let extra = u16::from_le_bytes(data[at + 30..at + 32].try_into().unwrap()) as usize;
        let comment = u16::from_le_bytes(data[at + 32..at + 34].try_into().unwrap()) as usize;
        at += 46 + name_len + extra + comment;
    }
    at
}

/// Position of the local header of central-directory record #`ordinal`.
fn local_record(data: &[u8], ordinal: usize) -> usize {
    let cd = cd_record(data, ordinal);
    u32::from_le_bytes(data[cd + CD_LOCAL_OFFSET..cd + CD_LOCAL_OFFSET + 4].try_into().unwrap())
        as usize
}

// ---------------------------------------------------------------------------
// DEX fixture builders
// ---------------------------------------------------------------------------

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for byte in bytes {
        a = (a + u32::from(*byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn push_uleb(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

/// Version-specific structural features the fixture really carries.
#[derive(Clone, Copy)]
struct DexVersionFeatures {
    /// 038+: method_handle and call_site sections exist.
    invoke_polymorphic_sections: bool,
    /// 039+: a `const-method-handle` instruction is present.
    const_method_handle: bool,
}

/// Builds a real one-class DEX for the given version tail.
///
/// `class_name` differs per version so the fixtures are not one image with a
/// patched magic: 035/037 share the format's identical section set (037 added
/// no new sections), 038 adds the method_handle/call_site sections the version
/// introduced, 039 additionally carries a `const-method-handle` instruction,
/// and 040 is structurally the 039 shape under its own magic (the format added
/// no new sections between 039 and 040).
fn make_version_dex(version: &[u8; 4], class_name: &str, features: DexVersionFeatures) -> Vec<u8> {
    let strings = [class_name, "Ljava/lang/Object;", "V", "m", "payload"];
    let string_ids_at = 0x70;
    let type_ids_at = string_ids_at + strings.len() * 4;
    let proto_ids_at = type_ids_at + 3 * 4;
    let method_ids_at = proto_ids_at + 12;
    let method_handles_at = method_ids_at + 8;
    let call_site_ids_at = if features.invoke_polymorphic_sections {
        method_handles_at + 8
    } else {
        method_ids_at
    };
    let class_defs_at = if features.invoke_polymorphic_sections {
        call_site_ids_at + 4
    } else {
        method_ids_at + 8
    };
    let data_at = class_defs_at + 32;

    let mut data = Vec::new();
    let mut string_offsets = Vec::with_capacity(strings.len());
    for value in &strings {
        string_offsets.push(data_at + data.len());
        data.push(value.len() as u8);
        data.extend_from_slice(value.as_bytes());
        data.push(0);
    }
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let mut insns: Vec<u8> = Vec::new();
    if features.const_method_handle {
        // const-method-handle v0, method_handle@0 (format 21c, opcode 0xfe).
        insns.extend_from_slice(&[0xfe, 0x00, 0x00, 0x00]);
    }
    // const-string v0, string@4 ("payload"); return-void.
    insns.extend_from_slice(&[0x1a, 0x00, 0x04, 0x00, 0x0e, 0x00]);
    let code_units = insns.len() as u32 / 2;
    let code_at = data_at + data.len();
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&code_units.to_le_bytes());
    data.extend_from_slice(&insns);
    let call_site_item_at = data_at + data.len();
    if features.invoke_polymorphic_sections {
        // call_site_item: method_handle_index uleb(0), empty arguments array.
        data.push(0);
        data.push(0);
    }
    let class_data_at = data_at + data.len();
    data.extend_from_slice(&[0, 0, 1, 0]); // sizes: one direct method
    push_uleb(&mut data, 0); // method_idx_diff
    push_uleb(&mut data, 0); // access_flags
    push_uleb(&mut data, code_at as u32); // code_off
    while !data.len().is_multiple_of(4) {
        data.push(0);
    }
    let map_at = data_at + data.len();

    let mut map_items: Vec<(u16, u32, u32)> = vec![
        (0x0000, 1, 0),
        (0x0001, strings.len() as u32, string_ids_at as u32),
        (0x0002, 3, type_ids_at as u32),
        (0x0003, 1, proto_ids_at as u32),
        (0x0005, 1, method_ids_at as u32),
    ];
    if features.invoke_polymorphic_sections {
        map_items.push((0x0008, 1, method_handles_at as u32));
        map_items.push((0x0007, 1, call_site_ids_at as u32));
    }
    map_items.push((0x0006, 1, class_defs_at as u32));
    map_items.push((0x2002, strings.len() as u32, string_offsets[0] as u32));
    map_items.push((0x2001, 1, code_at as u32));
    map_items.push((0x2000, 1, class_data_at as u32));
    let total = map_at + 4 + (map_items.len() + 1) * 12;
    map_items.push((0x1000, 1, map_at as u32));

    let mut out = vec![0u8; total];
    out[..4].copy_from_slice(b"dex\n");
    out[4..8].copy_from_slice(version);
    write_u32(&mut out, 0x20, total as u32);
    write_u32(&mut out, 0x24, 0x70);
    write_u32(&mut out, 0x28, 0x1234_5678);
    write_u32(&mut out, 0x34, map_at as u32);
    write_u32(&mut out, 0x38, strings.len() as u32);
    write_u32(&mut out, 0x3c, string_ids_at as u32);
    write_u32(&mut out, 0x40, 3);
    write_u32(&mut out, 0x44, type_ids_at as u32);
    write_u32(&mut out, 0x48, 1);
    write_u32(&mut out, 0x4c, proto_ids_at as u32);
    write_u32(&mut out, 0x58, 1);
    write_u32(&mut out, 0x5c, method_ids_at as u32);
    write_u32(&mut out, 0x60, 1);
    write_u32(&mut out, 0x64, class_defs_at as u32);
    write_u32(&mut out, 0x68, (total - data_at) as u32);
    write_u32(&mut out, 0x6c, data_at as u32);

    for (index, offset) in string_offsets.iter().enumerate() {
        write_u32(&mut out, string_ids_at + index * 4, *offset as u32);
    }
    for (index, string_idx) in [0u32, 1, 2].iter().enumerate() {
        write_u32(&mut out, type_ids_at + index * 4, *string_idx);
    }
    // proto_id: shorty "V" (string 2), return type 2, no parameters.
    write_u32(&mut out, proto_ids_at, 2);
    write_u32(&mut out, proto_ids_at + 4, 2);
    write_u32(&mut out, proto_ids_at + 8, 0);
    // method_id: class 0, proto 0, name string 3 ("m").
    write_u16(&mut out, method_ids_at, 0);
    write_u16(&mut out, method_ids_at + 2, 0);
    write_u32(&mut out, method_ids_at + 4, 3);
    if features.invoke_polymorphic_sections {
        // method_handle #0: invoke-static on method 0.
        write_u16(&mut out, method_handles_at, 0x02);
        write_u16(&mut out, method_handles_at + 2, 0);
        write_u32(&mut out, method_handles_at + 4, 0);
        // call_site_id #0: offset of the call_site_item in the data section.
        write_u32(&mut out, call_site_ids_at, call_site_item_at as u32);
    }
    // class_def: type 0, public, super type 1, no source file.
    write_u32(&mut out, class_defs_at, 0);
    write_u32(&mut out, class_defs_at + 4, 1);
    write_u32(&mut out, class_defs_at + 8, 1);
    write_u32(&mut out, class_defs_at + 16, 0xFFFF_FFFF);
    write_u32(&mut out, class_defs_at + 24, class_data_at as u32);

    out[data_at..data_at + data.len()].copy_from_slice(&data);
    let mut at = map_at;
    write_u32(&mut out, at, map_items.len() as u32);
    at += 4;
    for (kind, size, offset) in map_items {
        write_u16(&mut out, at, kind);
        write_u32(&mut out, at + 4, size);
        write_u32(&mut out, at + 8, offset);
        at += 12;
    }
    assert_eq!(at, total, "map layout must reach the file end");

    let signature = sha::sha1(&out[32..]);
    out[12..32].copy_from_slice(&signature);
    let checksum = adler32(&out[12..]);
    write_u32(&mut out, 8, checksum);
    out
}

/// make_dex with a corrupted SHA-1 signature but a correct checksum: the
/// IN-04 mismatch flavor.
fn sha1_mismatch_dex() -> Vec<u8> {
    let mut out = support::dex::make_dex();
    out[12..32].fill(0xCD);
    let checksum = adler32(&out[12..]);
    write_u32(&mut out, 8, checksum);
    out
}

/// Builds a 041 container whose members share one string pool: member 0 owns
/// the pool, later members' string_ids point back into member 0's span, which
/// is the container's cross-member addressing.
fn make_041_container(member_classes: &[&str]) -> Vec<u8> {
    const HEADER: usize = 0x78;

    // Shared pool: five strings per member, in order.
    let mut pool = Vec::new();
    for class in member_classes {
        for value in [*class, "Ljava/lang/Object;", "V", "m", "payload"] {
            pool.push(value.len() as u8);
            pool.extend_from_slice(value.as_bytes());
            pool.push(0);
        }
    }

    struct Plan {
        base: usize,
        string_ids_at: usize,
        type_ids_at: usize,
        proto_ids_at: usize,
        method_ids_at: usize,
        class_defs_at: usize,
        data_at: usize,
        code_at: usize,
        class_data_at: usize,
        map_at: usize,
        end: usize,
        string_base: usize,
    }
    let mut plans = Vec::new();
    let mut base = 0usize;
    for (index, string_base) in (0..member_classes.len()).map(|i| (i, i * 5)) {
        let string_ids_at = base + HEADER;
        let type_ids_at = string_ids_at + 20;
        let proto_ids_at = type_ids_at + 12;
        let method_ids_at = proto_ids_at + 12;
        let class_defs_at = method_ids_at + 8;
        let data_at = class_defs_at + 32;
        let after_pool = if index == 0 { data_at + pool.len() } else { data_at };
        let code_at = (after_pool + 3) & !3;
        let class_data_at = code_at + 16 + 3 * 2;
        let map_at = (class_data_at + 8 + 3) & !3;
        let map_items = 9 + usize::from(index == 0);
        let end = map_at + 4 + map_items * 12;
        plans.push(Plan {
            base,
            string_ids_at,
            type_ids_at,
            proto_ids_at,
            method_ids_at,
            class_defs_at,
            data_at,
            code_at,
            class_data_at,
            map_at,
            end,
            string_base,
        });
        base = end;
    }
    let total = base;
    let pool_at = plans[0].data_at;
    let member_strings =
        |member: usize| [member_classes[member], "Ljava/lang/Object;", "V", "m", "payload"];

    let mut out = vec![0u8; total];
    for (member_index, plan) in plans.iter().enumerate() {
        let base = plan.base;
        out[base..base + 8].copy_from_slice(b"dex\n041\0");
        write_u32(&mut out, base + 0x20, (plan.end - base) as u32);
        write_u32(&mut out, base + 0x24, HEADER as u32);
        write_u32(&mut out, base + 0x28, 0x1234_5678);
        write_u32(&mut out, base + 0x34, plan.map_at as u32);
        write_u32(&mut out, base + 0x38, 5);
        write_u32(&mut out, base + 0x3c, plan.string_ids_at as u32);
        write_u32(&mut out, base + 0x40, 3);
        write_u32(&mut out, base + 0x44, plan.type_ids_at as u32);
        write_u32(&mut out, base + 0x48, 1);
        write_u32(&mut out, base + 0x4c, plan.proto_ids_at as u32);
        write_u32(&mut out, base + 0x58, 1);
        write_u32(&mut out, base + 0x5c, plan.method_ids_at as u32);
        write_u32(&mut out, base + 0x60, 1);
        write_u32(&mut out, base + 0x64, plan.class_defs_at as u32);
        // Container fields.
        write_u32(&mut out, base + 0x70, total as u32);
        write_u32(&mut out, base + 0x74, base as u32);

        // string_ids point into the shared pool (member 0's span).
        let strings = member_strings(member_index);
        let mut pool_cursor = pool_at;
        for (index, string) in strings.iter().enumerate() {
            write_u32(&mut out, plan.string_ids_at + index * 4, pool_cursor as u32);
            pool_cursor += 1 + string.len() + 1;
        }
        for (index, value) in [plan.string_base as u32, plan.string_base as u32 + 1, plan.string_base as u32 + 2]
            .iter()
            .enumerate()
        {
            write_u32(&mut out, plan.type_ids_at + index * 4, *value);
        }
        write_u32(&mut out, plan.proto_ids_at, plan.string_base as u32 + 2);
        write_u32(&mut out, plan.proto_ids_at + 4, plan.string_base as u32 + 2);
        write_u32(&mut out, plan.proto_ids_at + 8, 0);
        write_u16(&mut out, plan.method_ids_at, 0);
        write_u16(&mut out, plan.method_ids_at + 2, 0);
        write_u32(&mut out, plan.method_ids_at + 4, plan.string_base as u32 + 3);
        write_u32(&mut out, plan.class_defs_at, 0);
        write_u32(&mut out, plan.class_defs_at + 4, 1);
        write_u32(&mut out, plan.class_defs_at + 8, 1);
        write_u32(&mut out, plan.class_defs_at + 16, 0xFFFF_FFFF);
        write_u32(&mut out, plan.class_defs_at + 24, plan.class_data_at as u32);

        // Data: the pool once (member 0), then code and class_data per member.
        if member_index == 0 {
            out[plan.data_at..plan.data_at + pool.len()].copy_from_slice(&pool);
        }
        write_u16(&mut out, plan.code_at, 1); // registers
        write_u16(&mut out, plan.code_at + 2, 0);
        write_u16(&mut out, plan.code_at + 4, 0);
        write_u16(&mut out, plan.code_at + 6, 0);
        write_u32(&mut out, plan.code_at + 8, 0);
        write_u32(&mut out, plan.code_at + 12, 3);
        // const-string v0, string@(base+4); return-void
        write_u16(&mut out, plan.code_at + 16, 0x001a);
        write_u16(&mut out, plan.code_at + 18, (plan.string_base + 4) as u16);
        write_u16(&mut out, plan.code_at + 20, 0x000e);
        let mut class_data = Vec::new();
        class_data.extend_from_slice(&[0, 0, 1, 0]);
        push_uleb(&mut class_data, 0);
        push_uleb(&mut class_data, 0);
        push_uleb(&mut class_data, plan.code_at as u32);
        assert_eq!(class_data.len(), 8, "layout plan assumes an 8-byte class_data");
        out[plan.class_data_at..plan.class_data_at + 8].copy_from_slice(&class_data);

        let mut items: Vec<(u16, u32, u32)> = vec![
            (0x0000, 1, 0),
            (0x0001, 5, plan.string_ids_at as u32),
            (0x0002, 3, plan.type_ids_at as u32),
            (0x0003, 1, plan.proto_ids_at as u32),
            (0x0005, 1, plan.method_ids_at as u32),
            (0x0006, 1, plan.class_defs_at as u32),
        ];
        if member_index == 0 {
            items.push((0x2002, (member_classes.len() * 5) as u32, pool_at as u32));
        }
        items.push((0x2001, 1, plan.code_at as u32));
        items.push((0x2000, 1, plan.class_data_at as u32));
        items.push((0x1000, 1, plan.map_at as u32));
        write_u32(&mut out, plan.map_at, items.len() as u32);
        let mut at = plan.map_at + 4;
        for (kind, size, offset) in items {
            write_u16(&mut out, at, kind);
            write_u32(&mut out, at + 4, size);
            write_u32(&mut out, at + 8, offset);
            at += 12;
        }
        assert_eq!(at, plan.end, "member map layout must tile");
    }

    // Integrity fields per member, computed after every patch above. The
    // signature covers [base+32..end) and is written first; the checksum
    // covers [base+12..end) — including the signature — so it must be
    // computed last, exactly like the DEX format's own finalize order.
    for plan in &plans {
        let signature = sha::sha1(&out[plan.base + 32..plan.end]);
        out[plan.base + 12..plan.base + 32].copy_from_slice(&signature);
        let checksum = adler32(&out[plan.base + 12..plan.end]);
        write_u32(&mut out, plan.base + 8, checksum);
    }
    out
}

/// One of the broken-container variants for the IN-03 rejection fixture.
fn make_bad_container(kind: u32) -> Vec<u8> {
    let mut container = make_041_container(&["Lexample/B1;", "Lexample/B2;"]);
    match kind {
        0 => write_u32(&mut container, 0x20, 0x20), // zero/undersized member
        1 => {
            let total = container.len() as u32;
            write_u32(&mut container, 0x20, total); // overshoot
        }
        _ => write_u32(&mut container, 0x74, 8), // contradictory self offset
    }
    container
}

/// The committed A02 fixture inputs, as (name, builder) pairs. The drift test
/// below pins the committed bytes to these builders.
fn a02_fixture_inputs() -> Vec<(String, Vec<u8>)> {
    let base_dex = support::dex::make_dex();
    let v037 = make_version_dex(
        b"037\0",
        "Lexample/V037;",
        DexVersionFeatures { invoke_polymorphic_sections: false, const_method_handle: false },
    );
    let v038 = make_version_dex(
        b"038\0",
        "Lexample/V038;",
        DexVersionFeatures { invoke_polymorphic_sections: true, const_method_handle: false },
    );
    let v039 = make_version_dex(
        b"039\0",
        "Lexample/V039;",
        DexVersionFeatures { invoke_polymorphic_sections: true, const_method_handle: true },
    );
    let v040 = make_version_dex(
        b"040\0",
        "Lexample/V040;",
        DexVersionFeatures { invoke_polymorphic_sections: true, const_method_handle: true },
    );
    // The 035 member of the version matrix uses its own real image, not
    // `make_dex`: the matrix test proves the payload carries no
    // const-method-handle opcode bytes, and `make_dex`'s string_ids happen to
    // contain the byte pair 0xFE 0x00 (the offset 254 of its "second"
    // string), which those opcode bytes are indistinguishable from.
    let v035 = make_version_dex(
        b"035\0",
        "Lexample/Test;",
        DexVersionFeatures { invoke_polymorphic_sections: false, const_method_handle: false },
    );
    let container_single = make_041_container(&["Lexample/Member;"]);
    let container_multi = make_041_container(&["Lexample/M1;", "Lexample/M2;"]);
    // Unknown versions: the v037 bytes with only the magic tail exchanged
    // (the magic is covered by neither the checksum nor the signature).
    let with_tail = |tail: &[u8; 4]| {
        let mut dex = v037.clone();
        dex[4..8].copy_from_slice(tail);
        dex
    };
    let unknown_036 = with_tail(b"036\0");
    let unknown_099 = with_tail(b"099\0");

    let mut inputs: Vec<(String, Vec<u8>)> = vec![
        (
            "in01-root-dex-priority-and-dupes.apk".into(),
            build_contract_zip(&[
                EntrySpec::stored("other.dex", &base_dex),
                EntrySpec::stored("assets/nested.dex", &base_dex),
                EntrySpec::deflated("classes.dex", &base_dex),
                EntrySpec::stored("classes.dex", &base_dex),
                EntrySpec::stored("classes2.dex", &base_dex),
            ]),
        ),
        (
            "in01-fallback-duplicate-names.apk".into(),
            build_contract_zip(&[
                EntrySpec::deflated("a.dex", &base_dex),
                EntrySpec::stored("b.dex", &base_dex),
                EntrySpec::stored("a.dex", &base_dex),
                EntrySpec::stored("AndroidManifest.xml", b"<manifest/>"),
                EntrySpec::stored("assets/deep/nested.dex", &base_dex),
            ]),
        ),
        (
            "in01-no-dex-query-notfound.apk".into(),
            build_contract_zip(&[EntrySpec::stored("AndroidManifest.xml", b"<manifest/>")]),
        ),
        (
            "in02-entry-decoding-matrix.apk".into(),
            build_contract_zip(&[
                EntrySpec::stored("classes.dex", &base_dex),
                EntrySpec::deflated("classes2.dex", &base_dex),
                EntrySpec::streamed("classes3.dex", &base_dex, true, true),
                EntrySpec::streamed("classes4.dex", &base_dex, false, false),
                EntrySpec::stored("assets/empty-stored.bin", b""),
                EntrySpec::deflated("assets/empty-deflate.bin", b""),
            ]),
        ),
        (
            "in02-bad-crc.apk".into(),
            build_contract_zip(&[
                EntrySpec::stored("classes.dex", &base_dex),
                EntrySpec::stored("assets/unrelated.png", b"unrelated payload"),
            ]),
        ),
        (
            "in02-zip64-rejected.apk".into(),
            build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]),
        ),
        (
            "in02-encrypted-rejected.apk".into(),
            build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]),
        ),
        (
            "in03-dex-versions.apk".into(),
            build_contract_zip(&[
                EntrySpec::stored("classes.dex", &v035),
                EntrySpec::deflated("classes2.dex", &v037),
                EntrySpec::stored("classes3.dex", &v038),
                EntrySpec::deflated("classes4.dex", &v039),
                EntrySpec::stored("classes5.dex", &v040),
            ]),
        ),
        (
            "in03-container-041-members.apk".into(),
            build_contract_zip(&[
                EntrySpec::deflated("classes.dex", &container_single),
                EntrySpec::stored("classes2.dex", &container_multi),
            ]),
        ),
        (
            "in03-compactdex-odex-rejected.apk".into(),
            build_contract_zip(&[
                EntrySpec::stored("classes.dex", b"cdex038\x00compact payload"),
                EntrySpec::stored("classes2.dex", b"dey036\x00odex payload"),
            ]),
        ),
        (
            "in03-unknown-version-rejected.apk".into(),
            build_contract_zip(&[
                EntrySpec::stored("classes.dex", &unknown_036),
                EntrySpec::stored("classes2.dex", &unknown_099),
            ]),
        ),
        (
            "in03-bad-container-rejected.apk".into(),
            build_contract_zip(&[
                EntrySpec::stored("classes.dex", &make_bad_container(0)),
                EntrySpec::stored("classes2.dex", &make_bad_container(1)),
                EntrySpec::stored("classes3.dex", &make_bad_container(2)),
            ]),
        ),
        (
            "in04-sha1-mismatch.apk".into(),
            build_contract_zip(&[EntrySpec::stored("classes.dex", &sha1_mismatch_dex())]),
        ),
    ];

    // Post-hoc corruptions that need byte positions.
    {
        let bad_crc = inputs
            .iter_mut()
            .find(|(name, _)| name == "in02-bad-crc.apk")
            .expect("bad-crc fixture registered");
        let first = cd_record(&bad_crc.1, 0) + CD_CRC;
        write_u32(&mut bad_crc.1, first, 0xDEAD_BEEF);
        let second = cd_record(&bad_crc.1, 1) + CD_CRC;
        write_u32(&mut bad_crc.1, second, 0xBAD0_BAD0);

        let zip64 = inputs
            .iter_mut()
            .find(|(name, _)| name == "in02-zip64-rejected.apk")
            .expect("zip64 fixture registered");
        let eocd = find_eocd(&zip64.1);
        write_u32(&mut zip64.1, eocd + 16, u32::MAX); // cd offset placeholder

        let encrypted = inputs
            .iter_mut()
            .find(|(name, _)| name == "in02-encrypted-rejected.apk")
            .expect("encrypted fixture registered");
        let cd = cd_record(&encrypted.1, 0);
        write_u16(&mut encrypted.1, cd + CD_FLAGS, 0x0001);
        let local = local_record(&encrypted.1, 0);
        write_u16(&mut encrypted.1, local + LH_FLAGS, 0x0001);
    }
    inputs
}

// ---------------------------------------------------------------------------
// Pipeline helper: catalog -> selection -> read -> validate
// ---------------------------------------------------------------------------

struct OpenedEntry {
    ordinal: u32,
    raw_name: Vec<u8>,
    bytes: Vec<u8>,
}

/// The selection facts a test needs without borrowing the catalog.
#[derive(Debug)]
struct SelectionSummary {
    selected_ordinals: Vec<u32>,
    used_fallback: bool,
    duplicates: Vec<(Vec<u8>, Vec<u32>)>,
}

fn summarize(catalog: &zip::ArchiveCatalog) -> SelectionSummary {
    let selection = select_root_dexes(catalog);
    SelectionSummary {
        selected_ordinals: selection.selected.iter().map(|entry| entry.ordinal).collect(),
        used_fallback: selection.used_fallback,
        duplicates: selection
            .duplicates
            .iter()
            .map(|duplicate| (duplicate.name.clone(), duplicate.ordinals.clone()))
            .collect(),
    }
}

/// Runs the A02 pipeline over an APK image and returns the catalog, the root
/// selection summary, the decoded selected entries and the diagnostics.
fn open_apk(
    apk: &[u8],
) -> (zip::ArchiveCatalog, SelectionSummary, Vec<OpenedEntry>, Vec<model::Diagnostic>) {
    let catalog = parse_catalog(apk, &InputLimits::DEFAULT).expect("catalog parses");
    let selection = select_root_dexes(&catalog);
    let artifact = artifact_of(apk);
    let control = never_cancel();
    let mut decoded_total = 0u64;
    let mut entries = Vec::new();
    let mut diagnostics = Vec::new();
    for entry in &selection.selected {
        let bytes =
            read_entry(apk, entry, &InputLimits::DEFAULT, &mut decoded_total, &control)
                .unwrap_or_else(|error| panic!("read {}: {error}", entry.display()));
        let (views, entry_diagnostics) =
            validate_dex_entry(artifact, entry.ordinal, &entry.raw_name, &bytes, &control)
                .unwrap_or_else(|error| panic!("validate {}: {error}", entry.display()));
        assert!(!views.views.is_empty());
        diagnostics.extend(entry_diagnostics);
        entries.push(OpenedEntry { ordinal: entry.ordinal, raw_name: entry.raw_name.clone(), bytes });
    }
    let summary = SelectionSummary {
        selected_ordinals: selection.selected.iter().map(|entry| entry.ordinal).collect(),
        used_fallback: selection.used_fallback,
        duplicates: selection
            .duplicates
            .iter()
            .map(|duplicate| (duplicate.name.clone(), duplicate.ordinals.clone()))
            .collect(),
    };
    (catalog, summary, entries, diagnostics)
}

/// All logical views of the opened entries, in (entry, logical) order.
fn views_of(opened: &[OpenedEntry], apk: &[u8]) -> Vec<(u32, u32, String, usize, &'static str)> {
    let artifact = artifact_of(apk);
    let control = never_cancel();
    let mut out = Vec::new();
    for entry in opened {
        let (views, _) =
            validate_dex_entry(artifact, entry.ordinal, &entry.raw_name, &entry.bytes, &control)
                .expect("entry validates");
        for view in views.views {
            out.push((
                view.id().entry_ordinal(),
                view.id().logical_ordinal(),
                view.logical_name().to_owned(),
                view.header_offset(),
                view.version().as_str(),
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// IN-01: root DEX discovery, low-level half
// ---------------------------------------------------------------------------

#[test]
fn in01_root_classes_dex_win_over_fallback_and_nested_are_ignored() {
    let apk = read_input("in01-root-dex-priority-and-dupes.apk");
    let (catalog, summary, entries, _) = open_apk(&apk);
    // Central-directory order preserved, ordinals are raw CD positions.
    let all_names: Vec<String> =
        catalog.entries.iter().map(|entry| display_name(&entry.raw_name)).collect();
    assert_eq!(
        all_names,
        ["other.dex", "assets/nested.dex", "classes.dex", "classes.dex", "classes2.dex"]
    );
    assert!(!summary.used_fallback, "classes*.dex present suppresses the fallback");
    assert_eq!(summary.selected_ordinals, [2, 4], "first classes.dex (2) plus classes2.dex (4)");
    // Duplicate kept visible with both original ordinals.
    assert_eq!(summary.duplicates.len(), 1, "{:?}", summary.duplicates);
    assert_eq!(summary.duplicates[0].0, b"classes.dex".to_vec());
    assert_eq!(summary.duplicates[0].1, [2, 3]);
    // Both selected entries decode to the same DEX payload.
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].bytes, entries[1].bytes);
    assert_eq!(entries[0].bytes, support::dex::make_dex());
}

#[test]
fn in01_fallback_selects_any_root_dex_and_keeps_the_first_duplicate() {
    let apk = read_input("in01-fallback-duplicate-names.apk");
    let (catalog, summary, entries, _) = open_apk(&apk);
    assert_eq!(catalog.entries.len(), 5);
    assert!(summary.used_fallback);
    assert_eq!(summary.selected_ordinals, [0, 1], "a.dex first copy and b.dex; nested ignored");
    assert_eq!(summary.duplicates.len(), 1);
    assert_eq!(summary.duplicates[0].0, b"a.dex".to_vec());
    assert_eq!(summary.duplicates[0].1, [0, 2]);
    assert_eq!(entries.len(), 2);
}

#[test]
fn in01_dexless_archive_reports_notfound_for_dex_backed_operations() {
    let apk = read_input("in01-no-dex-query-notfound.apk");
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    assert_eq!(catalog.entries.len(), 1, "the manifest entry stays readable");
    let selection = select_root_dexes(&catalog);
    assert!(selection.selected.is_empty());
    assert!(!selection.used_fallback);
    let error = selection.require_selected().unwrap_err();
    assert_eq!(error.kind(), &ErrorKind::NotFound, "{error}");
}

// ---------------------------------------------------------------------------
// IN-02: archive entry decoding matrix
// ---------------------------------------------------------------------------

#[test]
fn in02_decodes_stored_deflate_empty_streams_and_both_descriptor_spellings() {
    let apk = read_input("in02-entry-decoding-matrix.apk");
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let control = never_cancel();
    let mut decoded_total = 0u64;
    let base_dex = support::dex::make_dex();
    for entry in &catalog.entries {
        let bytes =
            read_entry(&apk, entry, &InputLimits::DEFAULT, &mut decoded_total, &control)
                .unwrap_or_else(|error| panic!("read {}: {error}", entry.display()));
        let expected: &[u8] = if entry.raw_name.starts_with(b"classes") {
            &base_dex
        } else {
            b""
        };
        assert_eq!(bytes, expected, "entry {}", entry.display());
    }
    // The four selected DEX entries validate without warnings.
    let (_, summary, entries, diagnostics) = open_apk(&apk);
    assert_eq!(summary.selected_ordinals, [0, 1, 2, 3]);
    assert_eq!(entries.len(), 4);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn in02_local_header_disagreements_are_rejected() {
    let base_dex = support::dex::make_dex();
    let mut total = 0u64;

    let mut read_first = |apk: &[u8]| {
        let catalog = parse_catalog(apk, &InputLimits::DEFAULT).unwrap();
        read_entry(apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &never_cancel())
            .unwrap_err()
    };

    // Local name differs from the central-directory name.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let name_at = local_record(&apk, 0) + 30;
    apk[name_at] = b'X';
    assert_kind(&read_first(&apk), &ErrorKind::MalformedInput, "name");

    // Local method differs.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let method_at = local_record(&apk, 0) + LH_METHOD;
    write_u16(&mut apk, method_at, 8);
    assert_kind(&read_first(&apk), &ErrorKind::MalformedInput, "method");

    // Local key flags differ (descriptor bit flipped locally only).
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let flags_at = local_record(&apk, 0) + LH_FLAGS;
    write_u16(&mut apk, flags_at, 0x0008);
    assert_kind(&read_first(&apk), &ErrorKind::MalformedInput, "flags");

    // Without the descriptor flag, local CRC/sizes must match the directory.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let crc_at = local_record(&apk, 0) + 14;
    write_u32(&mut apk, crc_at, 0);
    assert_kind(&read_first(&apk), &ErrorKind::MalformedInput, "CRC/sizes");
}

#[test]
fn in02_bad_eocd_and_ranges_are_located_structural_errors() {
    let base_dex = support::dex::make_dex();
    let apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);

    // No EOCD at all.
    let truncated = &apk[..apk.len() - 30];
    let error = parse_catalog(truncated, &InputLimits::DEFAULT).unwrap_err();
    assert_kind(&error, &ErrorKind::MalformedInput, "end of central directory");

    // Central directory reaching past the EOCD position.
    let mut apk2 = apk.clone();
    let at = find_eocd(&apk2) + 16;
    write_u32(&mut apk2, at, 0);
    let error = parse_catalog(&apk2, &InputLimits::DEFAULT).unwrap_err();
    assert_kind(&error, &ErrorKind::MalformedInput, "reaches past the EOCD");

    // Bad central-directory signature with position.
    let mut apk3 = apk.clone();
    let cd = cd_record(&apk3, 0);
    apk3[cd + 3] = b'X';
    let error = parse_catalog(&apk3, &InputLimits::DEFAULT).unwrap_err();
    assert!(error.to_string().contains(&format!("at offset {cd}")), "{error}");

    // Name length reaching past the directory end.
    let mut apk4 = apk.clone();
    let at = cd_record(&apk4, 0) + 28;
    write_u32(&mut apk4, at, 0xFFFF);
    let error = parse_catalog(&apk4, &InputLimits::DEFAULT).unwrap_err();
    assert_kind(&error, &ErrorKind::MalformedInput, "reaches past the directory end");

    // Entry counts disagreeing with the directory contents.
    let mut apk5 = apk.clone();
    let at = find_eocd(&apk5) + 10;
    apk5[at] = 2; // total count 2, actual 1
    let error = parse_catalog(&apk5, &InputLimits::DEFAULT).unwrap_err();
    assert_kind(&error, &ErrorKind::MalformedInput, "declares 1 entries");
}

#[test]
fn in02_selected_entry_crc_mismatch_fails_with_entry_and_offset() {
    let apk = read_input("in02-bad-crc.apk");
    // The whole catalog (including the unrelated bad-CRC asset) stays valid.
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    assert_eq!(catalog.entries.len(), 2);
    let selection = select_root_dexes(&catalog);
    assert_eq!(selection.selected.len(), 1, "only the DEX entry is selected");
    let mut total = 0u64;
    let error = read_entry(
        &apk,
        selection.selected[0],
        &InputLimits::DEFAULT,
        &mut total,
        &never_cancel(),
    )
    .unwrap_err();
    assert_kind(&error, &ErrorKind::MalformedInput, "CRC-32 mismatch");
    assert!(error.to_string().contains("classes.dex"), "{error}");
    assert!(error.to_string().contains("offset"), "the error must locate the entry: {error}");
}

#[test]
fn in02_actual_size_and_trailing_stream_are_rejected() {
    let base_dex = support::dex::make_dex();
    let control = never_cancel();
    let mut total = 0u64;

    let read_first = |apk: &[u8], total: &mut u64| {
        let catalog = parse_catalog(apk, &InputLimits::DEFAULT).unwrap();
        read_entry(apk, &catalog.entries[0], &InputLimits::DEFAULT, total, &control)
            .unwrap_err()
    };

    // Declared uncompressed size above the actual decoded bytes.
    let mut apk = build_contract_zip(&[EntrySpec::deflated("classes.dex", &base_dex)]);
    let at = cd_record(&apk, 0) + CD_UNCOMPRESSED;
    write_u32(&mut apk, at, base_dex.len() as u32 + 64);
    let error = read_first(&apk, &mut total);
    assert!(error.to_string().contains("decoded"), "{error}");

    // Declared uncompressed size below the actual decoded bytes (decoded
    // stream runs past the declared size).
    let mut apk = build_contract_zip(&[EntrySpec::deflated("classes.dex", &base_dex)]);
    let at = cd_record(&apk, 0) + CD_UNCOMPRESSED;
    write_u32(&mut apk, at, 64);
    let error = read_first(&apk, &mut total);
    assert!(error.to_string().contains("exceed the declared"), "{error}");

    // Stored entry whose sizes disagree.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let at = cd_record(&apk, 0) + CD_COMPRESSED;
    write_u32(&mut apk, at, 3);
    let error = read_first(&apk, &mut total);
    assert!(error.to_string().contains("stored sizes disagree"), "{error}");

    // Junk compressed bytes after the deflate stream end, inside the declared
    // compressed range: the stream must be consumed completely.
    let mut stream = deflate_raw(&base_dex);
    stream.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &stream)]);
    let cd = cd_record(&apk, 0);
    let local = local_record(&apk, 0);
    write_u16(&mut apk, cd + CD_METHOD, 8);
    write_u32(&mut apk, cd + CD_CRC, crc32(&base_dex));
    write_u32(&mut apk, cd + CD_COMPRESSED, stream.len() as u32);
    write_u32(&mut apk, cd + CD_UNCOMPRESSED, base_dex.len() as u32);
    write_u16(&mut apk, local + LH_METHOD, 8);
    write_u32(&mut apk, local + 14, crc32(&base_dex));
    write_u32(&mut apk, local + 18, stream.len() as u32);
    write_u32(&mut apk, local + 22, base_dex.len() as u32);
    let error = read_first(&apk, &mut total);
    assert!(error.to_string().contains("follow the end"), "{error}");

    // Truncated deflate stream.
    let mut stream = deflate_raw(&base_dex);
    stream.truncate(stream.len() - 2);
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &stream)]);
    let cd = cd_record(&apk, 0);
    let local = local_record(&apk, 0);
    write_u16(&mut apk, cd + CD_METHOD, 8);
    write_u32(&mut apk, cd + CD_CRC, crc32(&base_dex));
    write_u32(&mut apk, cd + CD_COMPRESSED, stream.len() as u32);
    write_u32(&mut apk, cd + CD_UNCOMPRESSED, base_dex.len() as u32);
    write_u16(&mut apk, local + LH_METHOD, 8);
    write_u32(&mut apk, local + 14, crc32(&base_dex));
    write_u32(&mut apk, local + 18, stream.len() as u32);
    write_u32(&mut apk, local + 22, base_dex.len() as u32);
    let error = read_first(&apk, &mut total);
    assert!(error.to_string().contains("truncated") || error.to_string().contains("declared"), "{error}");
}

#[test]
fn in02_descriptor_values_must_match_the_actual_stream() {
    let base_dex = support::dex::make_dex();
    let control = never_cancel();
    let mut total = 0u64;

    for spelling in [Descriptor::WithSignature, Descriptor::WithoutSignature] {
        let deflate = spelling == Descriptor::WithSignature;
        let apk = build_contract_zip(&[EntrySpec::streamed("classes.dex", &base_dex, deflate, !deflate)]);
        let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
        let bytes =
            read_entry(&apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &control)
                .unwrap_or_else(|error| panic!("{spelling:?}: {error}"));
        assert_eq!(bytes, base_dex);
    }

    // A descriptor size that disagrees with the actual stream.
    let mut apk =
        build_contract_zip(&[EntrySpec::streamed("classes.dex", &base_dex, true, true)]);
    let cd = cd_record(&apk, 0);
    let csize =
        u32::from_le_bytes(apk[cd + CD_COMPRESSED..cd + CD_COMPRESSED + 4].try_into().unwrap());
    let local = local_record(&apk, 0);
    let name_len = u16::from_le_bytes(apk[local + 26..local + 28].try_into().unwrap()) as usize;
    let descriptor_at = local + 30 + name_len + csize as usize + 4; // past the signature
    write_u32(&mut apk, descriptor_at + 8, 1); // wrong uncompressed size
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let error =
        read_entry(&apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &control)
            .unwrap_err();
    assert!(error.to_string().contains("data descriptor"), "{error}");

    // A truncated descriptor: the tail of the 12-byte descriptor is cut and
    // the central directory + EOCD slide over the gap (cutting the archive's
    // own last bytes would amputate the EOCD, which no catalog could parse).
    let mut apk =
        build_contract_zip(&[EntrySpec::streamed("classes.dex", &base_dex, true, false)]);
    {
        let cd = cd_record(&apk, 0);
        let csize =
            u32::from_le_bytes(apk[cd + CD_COMPRESSED..cd + CD_COMPRESSED + 4].try_into().unwrap())
                as usize;
        let local = local_record(&apk, 0);
        let name_len = u16::from_le_bytes(apk[local + 26..local + 28].try_into().unwrap()) as usize;
        let extra_len = u16::from_le_bytes(apk[local + 28..local + 30].try_into().unwrap()) as usize;
        let descriptor_end = local + 30 + name_len + extra_len + csize + 12;
        apk.drain(descriptor_end - 4..descriptor_end);
        let eocd = find_eocd(&apk);
        let cd_offset =
            u32::from_le_bytes(apk[eocd + 16..eocd + 20].try_into().unwrap());
        write_u32(&mut apk, eocd + 16, cd_offset - 4);
    }
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let error =
        read_entry(&apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &control)
            .unwrap_err();
    assert!(error.to_string().contains("descriptor"), "{error}");
}

#[test]
fn in02_zip64_encryption_multivolume_and_unknown_methods_are_unsupported() {
    let base_dex = support::dex::make_dex();
    let control = never_cancel();
    let mut total = 0u64;

    // 0xFFFF entry-count placeholder.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let at = find_eocd(&apk) + 8;
    write_u32(&mut apk, at, 0xFFFF);
    assert_kind(
        &parse_catalog(&apk, &InputLimits::DEFAULT).unwrap_err(),
        &ErrorKind::UnsupportedFormat,
        "ZIP64",
    );

    // 0xFFFFFFFF central-directory offset placeholder (the committed fixture).
    let apk = read_input("in02-zip64-rejected.apk");
    assert_kind(
        &parse_catalog(&apk, &InputLimits::DEFAULT).unwrap_err(),
        &ErrorKind::UnsupportedFormat,
        "ZIP64",
    );

    // Version needed 45 on the central-directory record.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let at = cd_record(&apk, 0) + 6;
    write_u16(&mut apk, at, 45);
    assert_kind(
        &parse_catalog(&apk, &InputLimits::DEFAULT).unwrap_err(),
        &ErrorKind::UnsupportedFormat,
        "version 45",
    );

    // 0xFFFFFFFF size placeholder in the directory.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let at = cd_record(&apk, 0) + CD_UNCOMPRESSED;
    write_u32(&mut apk, at, u32::MAX);
    assert_kind(
        &parse_catalog(&apk, &InputLimits::DEFAULT).unwrap_err(),
        &ErrorKind::UnsupportedFormat,
        "ZIP64",
    );

    // Multi-volume marker in the EOCD.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let at = find_eocd(&apk) + 4;
    write_u32(&mut apk, at, 1);
    assert_kind(
        &parse_catalog(&apk, &InputLimits::DEFAULT).unwrap_err(),
        &ErrorKind::UnsupportedFormat,
        "multi-volume",
    );

    // Encryption flag (the committed fixture fails at catalog level).
    let apk = read_input("in02-encrypted-rejected.apk");
    assert_kind(
        &parse_catalog(&apk, &InputLimits::DEFAULT).unwrap_err(),
        &ErrorKind::UnsupportedFormat,
        "encrypted",
    );

    // Unknown compression method, caught when the entry is read.
    let mut apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let cd_at = cd_record(&apk, 0);
    let local_at = local_record(&apk, 0) + LH_METHOD;
    write_u16(&mut apk, cd_at + CD_METHOD, 99);
    write_u16(&mut apk, local_at, 99);
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let error =
        read_entry(&apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &control)
            .unwrap_err();
    assert_kind(&error, &ErrorKind::UnsupportedFormat, "method 99");
}

#[test]
fn in02_resource_limits_are_enforced_with_actual_usage() {
    let base_dex = support::dex::make_dex();
    let control = never_cancel();

    // Archive entry count over a small override.
    let small_entries = InputLimits { max_archive_entries: 1, ..InputLimits::DEFAULT };
    let apk = build_contract_zip(&[
        EntrySpec::stored("classes.dex", &base_dex),
        EntrySpec::stored("classes2.dex", &base_dex),
    ]);
    let error = parse_catalog(&apk, &small_entries).unwrap_err();
    assert_kind(&error, &ErrorKind::ResourceLimit, "2 central-directory entries");

    // Single-entry declared size over a small override.
    let small_entry = InputLimits { max_entry_bytes: 16, ..InputLimits::DEFAULT };
    let apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let mut total = 0u64;
    let error =
        read_entry(&apk, &catalog.entries[0], &small_entry, &mut total, &control).unwrap_err();
    assert_kind(&error, &ErrorKind::ResourceLimit, "above the 16 single-entry limit");

    // Accumulated decoded bytes across entries over a small override.
    let small_total = InputLimits {
        max_total_decoded_bytes: base_dex.len() as u64 + 8,
        ..InputLimits::DEFAULT
    };
    let apk = build_contract_zip(&[
        EntrySpec::stored("classes.dex", &base_dex),
        EntrySpec::stored("classes2.dex", &base_dex),
    ]);
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let mut total = 0u64;
    read_entry(&apk, &catalog.entries[0], &small_total, &mut total, &control).unwrap();
    let error = read_entry(&apk, &catalog.entries[1], &small_total, &mut total, &control).unwrap_err();
    assert!(error.to_string().contains("across entries"), "{error}");
}

#[test]
fn in02_read_paths_observe_cancellation_and_deadlines() {
    let base_dex = support::dex::make_dex();
    let apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &base_dex)]);
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let mut total = 0u64;

    // User cancellation is visible before any work.
    let cancelled = AtomicBool::new(true);
    let probe = ControlProbe { cancelled: &cancelled, deadline: None };
    let error =
        read_entry(&apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &probe)
            .unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Cancelled { cause: CancelCause::User }));

    // An expired deadline reports the deadline cause.
    let flag = AtomicBool::new(false);
    let probe =
        ControlProbe { cancelled: &flag, deadline: Some(Instant::now() - Duration::from_millis(1)) };
    let error =
        read_entry(&apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &probe)
            .unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Cancelled { cause: CancelCause::Deadline }));

    // A large stored entry surfaces mid-copy cancellation through the 64 KiB
    // checkpoint cadence: the flag flips while the copy runs.
    let big = vec![0xA5u8; 32 * 1024 * 1024];
    let apk = build_contract_zip(&[EntrySpec::stored("assets/big.bin", &big)]);
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let flag = AtomicBool::new(false);
    let probe = ControlProbe { cancelled: &flag, deadline: None };
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(1));
            flag.store(true, Ordering::Relaxed);
        });
        let mut total = 0u64;
        read_entry(&apk, &catalog.entries[0], &InputLimits::DEFAULT, &mut total, &probe)
    });
    assert!(
        matches!(result.unwrap_err().kind(), ErrorKind::Cancelled { cause: CancelCause::User }),
        "mid-copy cancellation must surface"
    );
}

// ---------------------------------------------------------------------------
// IN-03: DEX version matrix and 041 containers
// ---------------------------------------------------------------------------

#[test]
fn in03_version_fixture_matrix_validates_every_supported_version() {
    let apk = read_input("in03-dex-versions.apk");
    let (_, summary, _, diagnostics) = open_apk(&apk);
    assert_eq!(summary.selected_ordinals, [0, 1, 2, 3, 4]);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
}

#[test]
fn in03_versioned_fixtures_carry_real_structural_differences() {
    let apk = read_input("in03-dex-versions.apk");
    let (_, _, entries, _) = open_apk(&apk);
    let per_entry: Vec<(String, u32, bool, Vec<u8>)> = entries
        .iter()
        .map(|entry| {
            let bytes = &entry.bytes;
            let map_off = u32::from_le_bytes(bytes[0x34..0x38].try_into().unwrap()) as usize;
            let map_size = u32::from_le_bytes(bytes[map_off..map_off + 4].try_into().unwrap());
            let has_const_method_handle =
                bytes.windows(2).any(|window| window == [0xfeu8, 0x00]);
            (
                display_name(&entry.raw_name),
                map_size,
                has_const_method_handle,
                entry.bytes.clone(),
            )
        })
        .collect();
    // 035/037: the shared baseline section set (10 map items).
    assert_eq!(per_entry[0].1, 10, "{}", per_entry[0].0);
    assert_eq!(per_entry[1].1, 10, "{}", per_entry[1].0);
    // 038/039/040: + method_handles + call_site_ids (12 map items).
    assert_eq!(per_entry[2].1, 12, "{}", per_entry[2].0);
    assert_eq!(per_entry[3].1, 12, "{}", per_entry[3].0);
    assert_eq!(per_entry[4].1, 12, "{}", per_entry[4].0);
    // const-method-handle only from 039 on.
    assert!(!per_entry[0].2 && !per_entry[1].2 && !per_entry[2].2);
    assert!(per_entry[3].2, "039 carries const-method-handle");
    assert!(per_entry[4].2, "040 carries const-method-handle");
    // Distinct class descriptors per version prove separate images.
    let class_names = [
        "Lexample/Test;", // support::make_dex's class (the 035 payload)
        "Lexample/V037;",
        "Lexample/V038;",
        "Lexample/V039;",
        "Lexample/V040;",
    ];
    for ((name, _, _, bytes), class) in per_entry.iter().zip(class_names) {
        assert!(
            bytes.windows(class.len()).any(|window| window == class.as_bytes()),
            "{name} lacks {class}"
        );
    }
    // Every entry validates against its version with stable identities.
    let views = views_of(&entries, &apk);
    let versions: Vec<&str> = views.iter().map(|(_, _, _, _, version)| *version).collect();
    assert_eq!(versions, ["035", "037", "038", "039", "040"]);
    let ids: Vec<(u32, u32)> = views.iter().map(|(e, l, _, _, _)| (*e, *l)).collect();
    assert_eq!(ids, [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0)]);
}

#[test]
fn in03_container_041_single_member_keeps_name_and_multi_member_shares_address_space() {
    let apk = read_input("in03-container-041-members.apk");
    let (_, summary, entries, diagnostics) = open_apk(&apk);
    assert_eq!(summary.selected_ordinals, [0, 1]);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let views = views_of(&entries, &apk);
    // The second member's header sits after the first member's own span.
    let first_member_size =
        u32::from_le_bytes(entries[1].bytes[0x20..0x24].try_into().unwrap()) as usize;
    assert_eq!(
        views,
        [
            (0, 0, "classes.dex".to_owned(), 0, "041"),
            (1, 0, "classes2.dex!classes1.dex".to_owned(), 0, "041"),
            (
                1,
                1,
                "classes2.dex!classes2.dex".to_owned(),
                first_member_size,
                "041"
            ),
        ],
        "logical names and ordinals must follow the chain"
    );

    let artifact = artifact_of(&apk);
    let control = never_cancel();
    // classes.dex: single-member 041, entry name, logical ordinal 0.
    let (single, single_diags) = validate_dex_entry(
        artifact,
        entries[0].ordinal,
        &entries[0].raw_name,
        &entries[0].bytes,
        &control,
    )
    .unwrap();
    assert!(single_diags.is_empty());
    assert_eq!(single.views.len(), 1);
    assert_eq!(single.views[0].logical_name(), "classes.dex");

    // classes2.dex: two members; the second member's string_ids point back
    // into the first member's span (cross-member addressing).
    let (multi, _) = validate_dex_entry(
        artifact,
        entries[1].ordinal,
        &entries[1].raw_name,
        &entries[1].bytes,
        &control,
    )
    .unwrap();
    assert_eq!(multi.views.len(), 2);
    let second = &multi.views[1];
    let second_base = second.header_offset();
    assert!(second_base > 0, "the second member starts after the first");
    let bytes = second.bytes();
    let string_ids_off =
        u32::from_le_bytes(bytes[second_base + 0x3c..second_base + 0x40].try_into().unwrap())
            as usize;
    let first_string_id =
        u32::from_le_bytes(bytes[string_ids_off..string_ids_off + 4].try_into().unwrap()) as usize;
    assert!(
        first_string_id < second_base,
        "member 2's string_ids must point into member 1's span: pointed at \
         {first_string_id}, member 2 starts at {second_base}"
    );
    // The whole container address space is shared: both views expose the same
    // physical buffer, only the header offset differs.
    assert!(std::ptr::eq(multi.views[0].bytes().as_ptr(), second.bytes().as_ptr()));
    // The second member still needs (and gets) its backend scratch.
    let scratch = backend_scratch(second, &[]).expect("041 member needs scratch");
    assert_eq!(scratch.source_header_offset, second_base);
}

#[test]
fn in03_compactdex_odex_and_unknown_versions_are_unsupported() {
    for (input, needle) in [
        ("in03-compactdex-odex-rejected.apk", "CompactDex"),
        ("in03-compactdex-odex-rejected.apk", "ODEX"),
        ("in03-unknown-version-rejected.apk", "outside the supported matrix"),
    ] {
        let apk = read_input(input);
        let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
        let control = never_cancel();
        let mut total = 0u64;
        let mut checked = 0;
        for entry in &catalog.entries {
            let bytes =
                read_entry(&apk, entry, &InputLimits::DEFAULT, &mut total, &control).unwrap();
            let error = validate_dex_entry(
                artifact_of(&apk),
                entry.ordinal,
                &entry.raw_name,
                &bytes,
                &control,
            )
            .unwrap_err();
            assert_kind(&error, &ErrorKind::UnsupportedFormat, needle);
            checked += 1;
        }
        assert!(checked >= 1);
    }
}

#[test]
fn in03_broken_containers_are_structural_errors_without_fallback() {
    let apk = read_input("in03-bad-container-rejected.apk");
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let control = never_cancel();
    let mut total = 0u64;
    let mut failures = 0;
    for entry in &catalog.entries {
        let bytes =
            read_entry(&apk, entry, &InputLimits::DEFAULT, &mut total, &control).unwrap();
        let error = validate_dex_entry(
            artifact_of(&apk),
            entry.ordinal,
            &entry.raw_name,
            &bytes,
            &control,
        )
        .unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::MalformedInput, "{error}");
        failures += 1;
    }
    assert_eq!(failures, 3, "every broken variant fails on its own");
}

// ---------------------------------------------------------------------------
// IN-04: integrity diagnostics
// ---------------------------------------------------------------------------

#[test]
fn in04_zero_checksum_fixture_warns_and_preserves_bytes() {
    let apk = read_input("g03-zero-checksum.apk");
    assert_eq!(
        apk,
        build_contract_zip(&[EntrySpec::stored(
            "classes.dex",
            &support::dex::zero_checksum_header(&support::dex::make_dex())
        )]),
        "the G03 fixture must stay the A00-committed bytes"
    );
    let before = apk.clone();
    let (_, summary, entries, diagnostics) = open_apk(&apk);
    assert_eq!(summary.selected_ordinals, [0]);
    assert_eq!(entries.len(), 1, "zeroed integrity fields must not stop analysis");
    assert_eq!(apk, before, "input bytes must remain unchanged");
    assert_eq!(diagnostics.len(), 2, "{diagnostics:?}");
    assert_eq!(diagnostics[0].code(), DiagnosticCode::DexChecksumMismatch);
    assert_eq!(diagnostics[1].code(), DiagnosticCode::DexSignatureMismatch);
    for diagnostic in &diagnostics {
        assert_eq!(diagnostic.severity(), Severity::Warning);
        assert_eq!(diagnostic.stage(), Stage::Dex);
        assert_eq!(diagnostic.dex().map(|id| id.entry_ordinal()), Some(0));
    }
    // Repeated validation is byte-identical and stable.
    let (_, _, again, diagnostics_again) = open_apk(&apk);
    assert_eq!(again[0].bytes, entries[0].bytes);
    assert_eq!(diagnostics_again.len(), 2);
}

#[test]
fn in04_sha1_mismatch_alone_warns_and_analysis_continues() {
    let apk = read_input("in04-sha1-mismatch.apk");
    let before = apk.clone();
    let (_, summary, entries, diagnostics) = open_apk(&apk);
    assert_eq!(summary.selected_ordinals, [0]);
    assert_eq!(apk, before);
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert_eq!(diagnostics[0].code(), DiagnosticCode::DexSignatureMismatch);
    assert_eq!(diagnostics[0].severity(), Severity::Warning);
    // The checksum is genuinely correct: only the signature was corrupted.
    assert!(
        !diagnostics.iter().any(|diagnostic| diagnostic.code() == DiagnosticCode::DexChecksumMismatch),
        "{diagnostics:?}"
    );
    // The view is fully usable and the DexEntry projection carries the facts.
    let (views, _) = validate_dex_entry(
        artifact_of(&apk),
        entries[0].ordinal,
        &entries[0].raw_name,
        &entries[0].bytes,
        &never_cancel(),
    )
    .unwrap();
    let dex_entry = views.dex_entry(0);
    assert_eq!(dex_entry.raw_entry_name(), b"classes.dex".to_vec());
    assert_eq!(dex_entry.version().as_str(), "035");
    assert_eq!(dex_entry.header_offset(), 0);
    assert_eq!(dex_entry.id().entry_ordinal(), 0);
}

#[test]
fn in04_structural_failures_are_errors_not_warnings() {
    let mut dex = support::dex::make_dex();
    write_u32(&mut dex, 0x20, 0x40); // contradictory file_size
    let apk = build_contract_zip(&[EntrySpec::stored("classes.dex", &dex)]);
    let catalog = parse_catalog(&apk, &InputLimits::DEFAULT).unwrap();
    let selection = select_root_dexes(&catalog);
    let mut total = 0u64;
    let bytes =
        read_entry(&apk, selection.selected[0], &InputLimits::DEFAULT, &mut total, &never_cancel())
            .unwrap();
    let error = validate_dex_entry(
        artifact_of(&apk),
        selection.selected[0].ordinal,
        &selection.selected[0].raw_name,
        &bytes,
        &never_cancel(),
    )
    .unwrap_err();
    assert_kind(&error, &ErrorKind::MalformedInput, "file_size");
}

// ---------------------------------------------------------------------------
// Fixture/manifest synchronization
// ---------------------------------------------------------------------------

#[test]
fn committed_a02_inputs_match_their_builders() {
    for (name, bytes) in a02_fixture_inputs() {
        let committed = read_input(&name);
        assert_eq!(
            committed, bytes,
            "{name}: committed bytes drifted from the registered generator"
        );
    }
    // The G03 input stays byte-identical to the A00 generator.
    assert_eq!(
        read_input("g03-zero-checksum.apk"),
        build_contract_zip(&[EntrySpec::stored(
            "classes.dex",
            &support::dex::zero_checksum_header(&support::dex::make_dex())
        )])
    );
}

#[test]
fn manifest_a02_cases_agree_with_the_committed_facts() {
    let manifest_text =
        fs::read_to_string(contracts_dir().join("manifest.json")).expect("read manifest");
    let manifest = support::json::parse(&manifest_text).expect("manifest parses");
    let cases = manifest.get("cases").and_then(|json| json.as_array()).expect("cases array");
    let mut checked = 0;
    for case in cases {
        if case.get("owner_package").and_then(|value| value.as_str()) != Some("A02")
            || case.get("status").and_then(|value| value.as_str()) != Some("active")
        {
            continue;
        }
        checked += 1;
        let case_id =
            case.get("case_id").and_then(|value| value.as_str()).unwrap_or_default().to_owned();
        let outcome = case
            .get("expected")
            .and_then(|expected| expected.get("outcome"))
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned();
        let input_name = case
            .get("input")
            .and_then(|input| input.get("path"))
            .and_then(|value| value.as_str())
            .and_then(|path| path.split('/').next_back())
            .unwrap_or_default()
            .to_owned();
        let bytes = read_input(&input_name);
        let recorded_sha =
            case.get("input").and_then(|input| input.get("sha256")).and_then(|v| v.as_str()).unwrap_or_default();
        assert_eq!(
            sha::hex_lower(&sha::sha256(&bytes)),
            recorded_sha,
            "{case_id}: manifest sha256 disagrees with the committed input"
        );

        let facts_path = case
            .get("expected")
            .and_then(|expected| expected.get("facts_path"))
            .and_then(|value| value.as_str())
            .map(str::to_owned);
        let Some(facts_path) = facts_path else {
            assert!(outcome.starts_with("error:"), "{case_id}: pass cases need facts");
            continue;
        };
        let facts_text = fs::read_to_string(contracts_dir().join(&facts_path))
            .unwrap_or_else(|error| panic!("{case_id}: read {facts_path}: {error}"));
        let facts = support::json::parse(&facts_text)
            .unwrap_or_else(|error| panic!("{case_id}: parse {facts_path}: {error}"));

        let control = never_cancel();
        let catalog = parse_catalog(&bytes, &InputLimits::DEFAULT);
        if outcome == "pass" {
            let catalog = catalog.unwrap_or_else(|error| panic!("{case_id}: {error}"));
            let selection = select_root_dexes(&catalog);
            let artifact = artifact_of(&bytes);
            let mut total = 0u64;
            let mut diagnostics = Vec::new();
            let mut rows = Vec::new();
            for entry in &selection.selected {
                let decoded = read_entry(&bytes, entry, &InputLimits::DEFAULT, &mut total, &control)
                    .unwrap_or_else(|error| panic!("{case_id}: {error}"));
                let (views, entry_diags) = validate_dex_entry(
                    artifact,
                    entry.ordinal,
                    &entry.raw_name,
                    &decoded,
                    &control,
                )
                .unwrap_or_else(|error| panic!("{case_id}: {error}"));
                diagnostics.extend(entry_diags);
                for view in views.views {
                    rows.push((
                        view.id().entry_ordinal(),
                        view.id().logical_ordinal(),
                        entry.display(),
                        view.version().as_str().to_owned(),
                        view.header_offset(),
                        decoded.len(),
                        view.logical_name().to_owned(),
                    ));
                }
            }
            let expected_rows = facts
                .get("dex_catalog")
                .and_then(|json| json.as_array())
                .unwrap_or_else(|| panic!("{case_id}: facts carry no dex_catalog"));
            assert_eq!(
                rows.len(),
                expected_rows.len(),
                "{case_id}: catalog row count disagrees with the facts"
            );
            for (row, expected) in rows.iter().zip(expected_rows) {
                let get = |key: &str| expected.get(key).and_then(|value| value.as_i64()).unwrap_or(-1);
                let get_str =
                    |key: &str| expected.get(key).and_then(|value| value.as_str()).unwrap_or_default();
                assert_eq!(row.0 as i64, get("entry_ordinal"), "{case_id}: entry_ordinal");
                assert_eq!(row.1 as i64, get("logical_ordinal"), "{case_id}: logical_ordinal");
                assert_eq!(row.2, get_str("raw_entry_name"), "{case_id}: raw_entry_name");
                assert_eq!(row.3, get_str("version"), "{case_id}: version");
                assert_eq!(row.4 as i64, get("header_offset"), "{case_id}: header_offset");
                assert_eq!(row.5 as i64, get("uncompressed_size"), "{case_id}: size");
            }
            let expected_diags: Vec<String> = facts
                .get("expected_diagnostics")
                .and_then(|json| json.as_array())
                .map(|array| {
                    array
                        .iter()
                        .map(|item| {
                            let code =
                                item.get("code").and_then(|value| value.as_str()).unwrap_or_default();
                            let severity = item
                                .get("severity")
                                .and_then(|value| value.as_str())
                                .unwrap_or_default();
                            assert_eq!(severity, "warning", "{case_id}: facts must say warning");
                            code.to_owned()
                })
                .collect()
                })
                .unwrap_or_default();
            let actual_codes: Vec<String> =
                diagnostics.iter().map(|d| d.code().as_str().to_owned()).collect();
            assert_eq!(actual_codes, expected_diags, "{case_id}: diagnostics disagree");
        } else {
            let kind = match outcome.strip_prefix("error:").unwrap_or_default() {
                "UnsupportedFormat" => ErrorKind::UnsupportedFormat,
                "MalformedInput" => ErrorKind::MalformedInput,
                "NotFound" => ErrorKind::NotFound,
                other => panic!("{case_id}: unexpected outcome kind {other}"),
            };
            let failed = match catalog {
                Err(error) => error.kind() == &kind,
                Ok(catalog) => {
                    let selection = select_root_dexes(&catalog);
                    selected_pipeline_fails(&bytes, &selection, &kind, &control)
                }
            };
            assert!(failed, "{case_id}: expected {outcome} but the pipeline succeeded");
        }
    }
    assert!(checked >= 13, "expected to verify all A02 cases, saw {checked}");
}

/// Whether reading/validating the selected entries (or the empty-selection
/// NotFound contract) fails exactly with `kind`.
fn selected_pipeline_fails(
    apk: &[u8],
    selection: &zip::RootSelection<'_>,
    kind: &ErrorKind,
    control: &ControlProbe<'_>,
) -> bool {
    let artifact = artifact_of(apk);
    let mut total = 0u64;
    for entry in &selection.selected {
        let failure = match read_entry(apk, entry, &InputLimits::DEFAULT, &mut total, control) {
            Err(error) => Some(error.kind().clone()),
            Ok(bytes) => validate_dex_entry(
                artifact,
                entry.ordinal,
                &entry.raw_name,
                &bytes,
                control,
            )
            .err()
            .map(|error| error.kind().clone()),
        };
        if let Some(observed_kind) = failure {
            return observed_kind == *kind;
        }
    }
    if selection.selected.is_empty() {
        let error = selection.require_selected().unwrap_err();
        return error.kind() == kind;
    }
    false
}

/// Regenerates the committed A02 fixture inputs (opt in with
/// `ASC_REGEN_FIXTURES=1`, mirroring the A00 harness), printing the
/// sha256/size pairs for manifest.json plus, per input, the pipeline facts
/// (dex_catalog rows and warning diagnostics) the manifest pass cases record.
#[test]
fn regenerate_fixture_inputs_when_explicitly_requested() {
    if std::env::var("ASC_REGEN_FIXTURES").ok().as_deref() != Some("1") {
        return;
    }
    let inputs = contracts_dir().join("inputs");
    fs::create_dir_all(&inputs).expect("create inputs directory");
    for (name, bytes) in a02_fixture_inputs() {
        fs::write(inputs.join(&name), &bytes).expect("write fixture input");
        println!("{name}: size {} sha256 {}", bytes.len(), sha::hex_lower(&sha::sha256(&bytes)));
    }
    // Maintenance aid for the manifest facts: run the A02 pipeline over every
    // registered input and print what a pass case must record.
    for (name, bytes) in a02_fixture_inputs() {
        println!("--- facts for {name}");
        let catalog = match parse_catalog(&bytes, &InputLimits::DEFAULT) {
            Ok(catalog) => catalog,
            Err(error) => {
                println!("catalog error {}: {error}", error.kind());
                continue;
            }
        };
        let selection = select_root_dexes(&catalog);
        let artifact = artifact_of(&bytes);
        let control = never_cancel();
        let mut total = 0u64;
        let mut diagnostics = Vec::new();
        for entry in &selection.selected {
            let decoded = match read_entry(&bytes, entry, &InputLimits::DEFAULT, &mut total, &control)
            {
                Ok(decoded) => decoded,
                Err(error) => {
                    println!("entry {} read error {}: {error}", entry.display(), error.kind());
                    continue;
                }
            };
            let (views, entry_diags) = match validate_dex_entry(
                artifact,
                entry.ordinal,
                &entry.raw_name,
                &decoded,
                &control,
            ) {
                Ok(result) => result,
                Err(error) => {
                    println!("entry {} validate error {}: {error}", entry.display(), error.kind());
                    continue;
                }
            };
            diagnostics.extend(entry_diags);
            for view in views.views {
                println!(
                    "row {{\"entry_ordinal\": {}, \"logical_ordinal\": {}, \
                     \"raw_entry_name\": \"{}\", \"version\": \"{}\", \"header_offset\": {}, \
                     \"uncompressed_size\": {}}}",
                    view.id().entry_ordinal(),
                    view.id().logical_ordinal(),
                    entry.display(),
                    view.version().as_str(),
                    view.header_offset(),
                    decoded.len()
                );
            }
        }
        for diagnostic in &diagnostics {
            println!(
                "diag {{\"code\": \"{}\", \"severity\": \"{}\"}}",
                diagnostic.code().as_str(),
                diagnostic.severity().as_str()
            );
        }
    }
}
