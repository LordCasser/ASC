//! LEB128 (Little-Endian Base 128) variable-length integer encoding/decoding.

/// Reads an unsigned LEB128 value from `buf` starting at `*offset`.
///
/// Updates `*offset` to point to the byte following the decoded value.
/// Direct fast unrolled implementation matching `tinydex`/Dalvik specification.
#[inline(always)]
pub fn read_uleb128_fast(buf: &[u8], offset: &mut usize) -> u32 {
    let pos = *offset;
    if pos >= buf.len() {
        return 0;
    }
    let b0 = buf[pos];
    if b0 < 128 {
        *offset = pos + 1;
        return b0 as u32;
    }

    let mut res = (b0 & 0x7f) as u32;
    if pos + 1 >= buf.len() {
        *offset = buf.len();
        return res;
    }
    let b1 = buf[pos + 1];
    res |= ((b1 & 0x7f) as u32) << 7;
    if b1 < 128 {
        *offset = pos + 2;
        return res;
    }

    if pos + 2 >= buf.len() {
        *offset = buf.len();
        return res;
    }
    let b2 = buf[pos + 2];
    res |= ((b2 & 0x7f) as u32) << 14;
    if b2 < 128 {
        *offset = pos + 3;
        return res;
    }

    if pos + 3 >= buf.len() {
        *offset = buf.len();
        return res;
    }
    let b3 = buf[pos + 3];
    res |= ((b3 & 0x7f) as u32) << 21;
    if b3 < 128 {
        *offset = pos + 4;
        return res;
    }

    if pos + 4 >= buf.len() {
        *offset = buf.len();
        return res;
    }
    let b4 = buf[pos + 4];
    res |= ((b4 & 0x7f) as u32) << 28;
    *offset = pos + 5;
    res
}

/// Reads a signed LEB128 value from `buf` starting at `*offset`.
///
/// Updates `*offset` to point to the byte following the decoded value.
#[inline(always)]
pub fn read_sleb128_fast(buf: &[u8], offset: &mut usize) -> i32 {
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    let mut byte: u8 = 0;

    while *offset < buf.len() {
        byte = buf[*offset];
        *offset += 1;
        result |= ((byte & 0x7f) as i32) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
    }

    if shift < 32 && (byte & 0x40) != 0 {
        result |= (!0i32).wrapping_shl(shift);
    }

    result
}

/// Reads an unsigned LEB128 value from `buf` at `pos`, returning `(value, byte_count)`.
#[inline]
pub fn read_uleb128(buf: &[u8], pos: usize) -> (u32, usize) {
    let mut offset = pos;
    let val = read_uleb128_fast(buf, &mut offset);
    (val, offset - pos)
}

/// Reads a signed LEB128 value from `buf` at `pos`, returning `(value, byte_count)`.
#[inline]
pub fn read_sleb128(buf: &[u8], pos: usize) -> (i32, usize) {
    let mut offset = pos;
    let val = read_sleb128_fast(buf, &mut offset);
    (val, offset - pos)
}

/// Returns the number of bytes occupied by the ULEB128 value at `pos`.
#[inline]
pub fn read_uleb128_len(buf: &[u8], pos: usize) -> usize {
    if pos >= buf.len() {
        return 0;
    }
    if buf[pos] < 128 {
        1
    } else if pos + 1 < buf.len() && buf[pos + 1] < 128 {
        2
    } else if pos + 2 < buf.len() && buf[pos + 2] < 128 {
        3
    } else if pos + 3 < buf.len() && buf[pos + 3] < 128 {
        4
    } else if pos + 4 < buf.len() && buf[pos + 4] < 128 {
        5
    } else {
        let mut p = pos + 5;
        while p < buf.len() && buf[p] >= 128 {
            p += 1;
        }
        if p < buf.len() {
            p - pos + 1
        } else {
            buf.len() - pos
        }
    }
}

/// Encodes an unsigned 32-bit integer as ULEB128 bytes.
pub fn write_uleb128(mut value: u32) -> Vec<u8> {
    let mut out = Vec::new();
    if value == 0 {
        return vec![0];
    }
    while value > 0x7f {
        out.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

/// Encodes a signed 32-bit integer as SLEB128 bytes.
pub fn write_sleb128(mut value: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut more = true;
    while more {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if (value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0) {
            more = false;
        } else {
            out.push(byte | 0x80);
            continue;
        }
        out.push(byte);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uleb128_roundtrip() {
        let test_values = [
            0u32, 1, 127, 128, 255, 256, 16383, 16384, 65535, 65536,
            0x1fffff, 0x200000, 0x0fffffff, 0x10000000, u32::MAX,
        ];
        for &val in &test_values {
            let encoded = write_uleb128(val);
            assert_eq!(read_uleb128_len(&encoded, 0), encoded.len());
            let mut offset = 0;
            let decoded = read_uleb128_fast(&encoded, &mut offset);
            assert_eq!(offset, encoded.len());
            assert_eq!(decoded, val);
        }
    }

    #[test]
    fn test_sleb128_roundtrip() {
        let test_values = [
            0i32, 1, -1, 63, -64, 64, -65, 127, -128, 128, -129,
            8191, -8192, 8192, -8193, 1000000, -1000000,
            i32::MAX, i32::MIN,
        ];
        for &val in &test_values {
            let encoded = write_sleb128(val);
            let mut offset = 0;
            let decoded = read_sleb128_fast(&encoded, &mut offset);
            assert_eq!(offset, encoded.len());
            assert_eq!(decoded, val);
        }
    }
}
