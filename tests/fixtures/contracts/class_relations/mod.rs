//! A20 byte-authored declaration fixtures, independent of the relation reader.
//! No methods/code are needed. Indexes are supplied by each test's expected
//! facts; both 035 and 041 use the same tables with container-absolute offsets.
#![allow(dead_code)]

use crate::support::sha;

pub fn read32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
pub fn write32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn align(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}
fn uleb(bytes: &mut Vec<u8>, mut n: u32) {
    loop {
        let more = n >> 7;
        bytes.push((n as u8 & 0x7f) | if more != 0 { 0x80 } else { 0 });
        n = more;
        if n == 0 {
            break;
        }
    }
}
pub fn finish_integrity(bytes: &mut [u8]) {
    let signature = sha::sha1(&bytes[32..]);
    bytes[12..32].copy_from_slice(&signature);
    let checksum = sha::adler32(&bytes[12..]);
    write32(bytes, 8, checksum);
}

pub fn dex(types: &[&str], classes: &[(u32, u32, Vec<u16>)]) -> Vec<u8> {
    member(types, classes, 0, false)
}

fn member(types: &[&str], classes: &[(u32, u32, Vec<u16>)], base: usize, v041: bool) -> Vec<u8> {
    let header = if v041 { 0x78 } else { 0x70 };
    let mut out = vec![0u8; header];
    out[..8].copy_from_slice(if v041 { b"dex\n041\0" } else { b"dex\n035\0" });
    write32(&mut out, 0x24, header as u32);
    write32(&mut out, 0x28, 0x12345678);
    let mut map = vec![(0u16, 1u32, base as u32)];
    let mut table = |size_at: usize, kind: u16, count: usize, width: usize| {
        if count == 0 {
            return 0;
        }
        let start = out.len();
        out.resize(start + count * width, 0);
        write32(&mut out, size_at, count as u32);
        write32(&mut out, size_at + 4, (base + start) as u32);
        map.push((kind, count as u32, (base + start) as u32));
        start
    };
    let strings = table(0x38, 1, types.len(), 4);
    let type_ids = table(0x40, 2, types.len(), 4);
    let defs = table(0x60, 6, classes.len(), 32);
    let data_start = out.len();
    for (index, _) in types.iter().enumerate() {
        write32(&mut out, type_ids + index * 4, index as u32);
    }
    let mut lists = Vec::new();
    for (index, (class, parent, interfaces)) in classes.iter().enumerate() {
        let at = defs + index * 32;
        write32(&mut out, at, *class);
        write32(&mut out, at + 4, 1);
        write32(&mut out, at + 8, *parent);
        write32(&mut out, at + 16, u32::MAX);
        if !interfaces.is_empty() {
            align(&mut out);
            let offset = (base + out.len()) as u32;
            lists.push(offset);
            write32(&mut out, at + 12, offset);
            out.extend_from_slice(&(interfaces.len() as u32).to_le_bytes());
            for item in interfaces {
                out.extend_from_slice(&item.to_le_bytes());
            }
        }
    }
    if !lists.is_empty() {
        map.push((0x1001, lists.len() as u32, lists[0]));
    }
    let string_data = (base + out.len()) as u32;
    for (index, text) in types.iter().enumerate() {
        let offset = (base + out.len()) as u32;
        write32(&mut out, strings + index * 4, offset);
        let units = text.encode_utf16().collect::<Vec<_>>();
        uleb(&mut out, units.len() as u32);
        for unit in units {
            match unit {
                0 => out.extend_from_slice(&[0xc0, 0x80]),
                1..=0x7f => out.push(unit as u8),
                0x80..=0x7ff => {
                    out.extend_from_slice(&[0xc0 | (unit >> 6) as u8, 0x80 | (unit & 63) as u8])
                }
                _ => out.extend_from_slice(&[
                    0xe0 | (unit >> 12) as u8,
                    0x80 | ((unit >> 6) & 63) as u8,
                    0x80 | (unit & 63) as u8,
                ]),
            }
        }
        out.push(0);
    }
    if !types.is_empty() {
        map.push((0x2002, types.len() as u32, string_data));
    }
    align(&mut out);
    let map_at = out.len();
    map.push((0x1000, 1, (base + map_at) as u32));
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (kind, count, offset) in map {
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
    }
    let len = out.len() as u32;
    write32(&mut out, 0x20, len);
    write32(&mut out, 0x34, (base + map_at) as u32);
    if !v041 {
        write32(&mut out, 0x68, len - data_start as u32);
        write32(&mut out, 0x6c, data_start as u32);
    }
    finish_integrity(&mut out);
    out
}

/// Member 1 references member 0's string data and interface list. Both members
/// define the same class descriptor with separate class_def/DexId identities.
pub fn container_041() -> Vec<u8> {
    let types = ["Lexample/Child;", "Lexample/Parent;", "Lexample/I;"];
    let classes = [(0, 1, vec![2])];
    let mut first = member(&types, &classes, 0, true);
    let base = first.len();
    let mut second = member(&types, &classes, base, true);
    let first_strings = read32(&first, 0x3c) as usize;
    let second_strings = read32(&second, 0x3c) as usize - base;
    for index in 0..types.len() {
        write32(
            &mut second,
            second_strings + index * 4,
            read32(&first, first_strings + index * 4),
        );
    }
    let first_defs = read32(&first, 0x64) as usize;
    let second_defs = read32(&second, 0x64) as usize - base;
    write32(
        &mut second,
        second_defs + 12,
        read32(&first, first_defs + 12),
    );
    let total = (first.len() + second.len()) as u32;
    write32(&mut first, 0x70, total);
    write32(&mut second, 0x70, total);
    write32(&mut second, 0x74, base as u32);
    finish_integrity(&mut first);
    finish_integrity(&mut second);
    first.extend_from_slice(&second);
    first
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Build a deterministic stored-entry ZIP containing the selected root DEXes.
pub fn apk(entries: &[(&str, &[u8])]) -> Vec<u8> {
    const VERSION: u16 = 20;
    const DOS_TIME: u16 = 0;
    const DOS_DATE: u16 = 0x21;

    let mut local = Vec::new();
    let mut central = Vec::new();
    for (name, payload) in entries {
        let name = name.as_bytes();
        let crc = crc32(payload);
        let offset = local.len() as u32;
        let size = payload.len() as u32;

        local.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut local, VERSION);
        push_u16(&mut local, 0);
        push_u16(&mut local, 0);
        push_u16(&mut local, DOS_TIME);
        push_u16(&mut local, DOS_DATE);
        push_u32(&mut local, crc);
        push_u32(&mut local, size);
        push_u32(&mut local, size);
        push_u16(&mut local, name.len() as u16);
        push_u16(&mut local, 0);
        local.extend_from_slice(name);
        local.extend_from_slice(payload);

        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, VERSION);
        push_u16(&mut central, VERSION);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, DOS_TIME);
        push_u16(&mut central, DOS_DATE);
        push_u32(&mut central, crc);
        push_u32(&mut central, size);
        push_u32(&mut central, size);
        push_u16(&mut central, name.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, offset);
        central.extend_from_slice(name);
    }

    let central_offset = local.len() as u32;
    let central_size = central.len() as u32;
    let mut output = local;
    output.extend_from_slice(&central);
    output.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, entries.len() as u16);
    push_u16(&mut output, entries.len() as u16);
    push_u32(&mut output, central_size);
    push_u32(&mut output, central_offset);
    push_u16(&mut output, 0);
    output
}

/// Many distinct type IDs alias one string. A single interface list fans out
/// to all IDs, so result struct capacities dominate the tiny text payload.
pub fn alias_type_fanout(count: u16) -> Vec<u8> {
    let count = usize::from(count);
    let strings = 112;
    let types = strings + 4;
    let defs = types + count * 4;
    let list = defs + 32;
    let mut out = vec![0u8; list];
    out[..8].copy_from_slice(b"dex\n035\0");
    write32(&mut out, 0x24, 112);
    write32(&mut out, 0x28, 0x12345678);
    write32(&mut out, 0x38, 1);
    write32(&mut out, 0x3c, strings as u32);
    write32(&mut out, 0x40, count as u32);
    write32(&mut out, 0x44, types as u32);
    write32(&mut out, 0x60, 1);
    write32(&mut out, 0x64, defs as u32);
    write32(&mut out, defs + 4, 1);
    write32(&mut out, defs + 8, u32::MAX);
    write32(&mut out, defs + 12, list as u32);
    write32(&mut out, defs + 16, u32::MAX);
    out.extend_from_slice(&(count as u32).to_le_bytes());
    for index in 0..count {
        out.extend_from_slice(&(index as u16).to_le_bytes());
    }
    let text = out.len();
    write32(&mut out, strings, text as u32);
    out.extend_from_slice(b"\x03LA;\0");
    align(&mut out);
    let map = out.len();
    let entries = [
        (0, 1, 0),
        (1, 1, strings),
        (2, count, types),
        (6, 1, defs),
        (0x1001, 1, list),
        (0x2002, 1, text),
        (0x1000, 1, map),
    ];
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (kind, count, offset) in entries {
        out.extend_from_slice(&(kind as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    let len = out.len();
    write32(&mut out, 0x20, len as u32);
    write32(&mut out, 0x34, map as u32);
    write32(&mut out, 0x68, (len - list) as u32);
    write32(&mut out, 0x6c, list as u32);
    finish_integrity(&mut out);
    out
}
