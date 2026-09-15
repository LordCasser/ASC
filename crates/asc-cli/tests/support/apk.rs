//! Minimal APK (ZIP) writer for contract fixtures.
//!
//! One stored entry per archive: local header + bytes + central directory +
//! EOCD, with a fixed DOS timestamp (1980-01-01 00:00:00) so the bytes are
//! reproducible. No deflate here on purpose - compressed entries arrive with
//! the IN-02 fixtures in A02, and keeping the A00 fixtures stored keeps the
//! generator independent of any zlib output version.

/// Reflected CRC-32 (the ZIP check value), implemented bitwise so the support
/// library stays standard-library only.
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

/// Wrap `dex` as a single stored entry named `name` (e.g. "classes.dex").
pub fn apk_with_single_dex(name: &str, dex: &[u8]) -> Vec<u8> {
    const VERSION: u16 = 20; // 2.0 - the minimum for stored entries
    const FLAGS: u16 = 0; // no data descriptor, no UTF-8 flag needed (ASCII)
    const METHOD_STORED: u16 = 0;
    const DOS_TIME: u16 = 0x0000; // 00:00:00
    const DOS_DATE: u16 = 0x0021; // 1980-01-01

    let crc = crc32(dex);
    let size = dex.len() as u32;
    let name = name.as_bytes();

    let mut out = Vec::with_capacity(30 + name.len() + dex.len() + 46 + name.len() + 22);

    // Local file header.
    out.extend_from_slice(b"PK\x03\x04");
    push_u16(&mut out, VERSION);
    push_u16(&mut out, FLAGS);
    push_u16(&mut out, METHOD_STORED);
    push_u16(&mut out, DOS_TIME);
    push_u16(&mut out, DOS_DATE);
    push_u32(&mut out, crc);
    push_u32(&mut out, size);
    push_u32(&mut out, size);
    push_u16(&mut out, name.len() as u16);
    push_u16(&mut out, 0); // extra length
    out.extend_from_slice(name);
    out.extend_from_slice(dex);

    // Central directory record for the single entry.
    let local_header_offset = 0u32;
    let central_directory_offset = out.len() as u32;
    out.extend_from_slice(b"PK\x01\x02");
    push_u16(&mut out, VERSION); // version made by (MS-DOS)
    push_u16(&mut out, VERSION); // version needed
    push_u16(&mut out, FLAGS);
    push_u16(&mut out, METHOD_STORED);
    push_u16(&mut out, DOS_TIME);
    push_u16(&mut out, DOS_DATE);
    push_u32(&mut out, crc);
    push_u32(&mut out, size);
    push_u32(&mut out, size);
    push_u16(&mut out, name.len() as u16);
    push_u16(&mut out, 0); // extra length
    push_u16(&mut out, 0); // comment length
    push_u16(&mut out, 0); // disk number start
    push_u16(&mut out, 0); // internal attributes
    push_u32(&mut out, 0); // external attributes
    push_u32(&mut out, local_header_offset);
    out.extend_from_slice(name);
    let central_directory_size = out.len() as u32 - central_directory_offset;

    // End of central directory.
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0); // this disk
    push_u16(&mut out, 0); // disk with the central directory
    push_u16(&mut out, 1); // entries on this disk
    push_u16(&mut out, 1); // total entries
    push_u32(&mut out, central_directory_size);
    push_u32(&mut out, central_directory_offset);
    push_u16(&mut out, 0); // comment length
    out
}
