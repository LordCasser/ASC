//! MUTF-8 codec owned by the scanner.
//!
//! DEX string data is MUTF-8, a UTF-8 variant: NUL is the two-byte `0xC0 0x80`
//! and supplementary characters appear as a *surrogate pair* of three-byte
//! sequences, so a decoder must accept surrogate-valued three-byte forms that
//! strict UTF-8 rejects. The default scanner uses this codec instead of the
//! vendored `droidsaw_dex::mutf8` (A03 removes that dependency); `decode_into`
//! and `decode_units` write UTF-16 units into a reusable buffer because the
//! hot per-candidate matching path must not allocate a `String` per string.
//!
//! The length prefix of a string_data item counts UTF-16 code units, not
//! bytes. `decode_units` is the scanner's entry point: it decodes exactly the
//! declared unit count - never reading past it - so the caller can require
//! the terminating NUL right there and treat short or overlong payloads as
//! malformed instead of decoding into a neighbouring item's bytes.

/// Why a byte slice is not valid MUTF-8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DecodeError {
    /// A multi-byte sequence ended before all of its continuation bytes.
    Truncated,
    /// A lead byte MUTF-8 never produces: `0x80..=0xBF` in lead position,
    /// `0xC1` (overlong), or a four-byte form `0xF0..=0xFF`.
    IllegalLead(u8),
    /// A continuation position held a byte without the `0x80` tag.
    IllegalContinuation(u8),
    /// The raw NUL terminator appeared before the declared unit count was
    /// decoded: the declared length disagrees with the payload.
    Terminator,
}

impl DecodeError {
    /// Stable description embedded in MalformedInput messages.
    pub(super) fn describe(&self) -> String {
        match self {
            DecodeError::Truncated => "truncated MUTF-8 sequence".to_owned(),
            DecodeError::IllegalLead(byte) => format!("illegal MUTF-8 lead byte 0x{byte:02x}"),
            DecodeError::IllegalContinuation(byte) => {
                format!("illegal MUTF-8 continuation byte 0x{byte:02x}")
            }
            DecodeError::Terminator => {
                "NUL terminator before the declared UTF-16 unit count".to_owned()
            }
        }
    }
}

/// Decodes NUL-free MUTF-8 bytes into `scratch`, which is cleared first.
///
/// The input must exclude the terminating NUL: a sequence cut short by the
/// terminator surfaces as `Truncated` or `IllegalContinuation`, both
/// malformed. Surrogate-valued units are passed through untouched; they stay
/// distinguishable in [`crate::model::DexText`].
#[allow(dead_code)] // A03 contract surface; used by tests and A08
pub(super) fn decode_into(data: &[u8], scratch: &mut Vec<u16>) -> Result<(), DecodeError> {
    scratch.clear();
    let mut index = 0;
    while index < data.len() {
        let lead = data[index];
        if lead < 0x80 {
            scratch.push(u16::from(lead));
            index += 1;
            continue;
        }
        let unit = match lead {
            0xC0 => {
                // Only the canonical two-byte NUL exists; anything else is
                // overlong encoding.
                let continuation = *data.get(index + 1).ok_or(DecodeError::Truncated)?;
                if continuation != 0x80 {
                    return Err(DecodeError::IllegalContinuation(continuation));
                }
                scratch.push(0);
                index += 2;
                continue;
            }
            0xC2..=0xDF => {
                let continuation = continuation_at(data, index + 1)?;
                (u16::from(lead & 0x1f) << 6) | u16::from(continuation & 0x3f)
            }
            0xE0..=0xEF => {
                let first = continuation_at(data, index + 1)?;
                let second = continuation_at(data, index + 2)?;
                (u16::from(lead & 0x0f) << 12)
                    | (u16::from(first & 0x3f) << 6)
                    | u16::from(second & 0x3f)
            }
            _ => return Err(DecodeError::IllegalLead(lead)),
        };
        scratch.push(unit);
        index += if lead >= 0xE0 { 3 } else { 2 };
    }
    Ok(())
}

/// The continuation byte at `index`, checked for the `10xxxxxx` tag.
fn continuation_at(data: &[u8], index: usize) -> Result<u8, DecodeError> {
    let byte = *data.get(index).ok_or(DecodeError::Truncated)?;
    if byte & 0xC0 == 0x80 {
        Ok(byte)
    } else {
        Err(DecodeError::IllegalContinuation(byte))
    }
}

/// Decodes exactly `declared` UTF-16 units from the head of `data` into
/// `scratch` (cleared first) and returns how many bytes they consumed.
///
/// This is the string_data reading rule: the length prefix counts units, so
/// the decoder stops after `declared` units *without reading further*, and
/// the caller verifies the terminating NUL at that position. A raw `0x00`
/// byte inside the units region is the terminator arriving early (the
/// declared count disagrees with the payload); running out of bytes first is
/// a truncation. Both surface as [`DecodeError`] instead of a replacement
/// decode, so a string can never silently swallow a neighbour payload's
/// bytes.
pub(super) fn decode_units(
    data: &[u8],
    declared: usize,
    scratch: &mut Vec<u16>,
) -> Result<usize, DecodeError> {
    scratch.clear();
    scratch.reserve(declared);
    let mut index = 0;
    while scratch.len() < declared {
        let lead = *data.get(index).ok_or(DecodeError::Truncated)?;
        if lead == 0 {
            return Err(DecodeError::Terminator);
        }
        if lead < 0x80 {
            scratch.push(u16::from(lead));
            index += 1;
            continue;
        }
        let unit = match lead {
            0xC0 => {
                // Only the canonical two-byte NUL exists; anything else is
                // overlong encoding.
                let continuation = *data.get(index + 1).ok_or(DecodeError::Truncated)?;
                if continuation != 0x80 {
                    return Err(DecodeError::IllegalContinuation(continuation));
                }
                0
            }
            0xC2..=0xDF => {
                let continuation = continuation_at(data, index + 1)?;
                (u16::from(lead & 0x1f) << 6) | u16::from(continuation & 0x3f)
            }
            0xE0..=0xEF => {
                let first = continuation_at(data, index + 1)?;
                let second = continuation_at(data, index + 2)?;
                (u16::from(lead & 0x0f) << 12)
                    | (u16::from(first & 0x3f) << 6)
                    | u16::from(second & 0x3f)
            }
            _ => return Err(DecodeError::IllegalLead(lead)),
        };
        scratch.push(unit);
        index += if lead >= 0xE0 { 3 } else { 2 };
    }
    Ok(index)
}

/// Allocating convenience over [`decode_into`].
#[allow(dead_code)]
pub(super) fn decode(data: &[u8]) -> Result<Vec<u16>, DecodeError> {
    let mut units = Vec::new();
    decode_into(data, &mut units)?;
    Ok(units)
}

/// Legacy-bridge helper: a `String` for display paths, replacing the previous
/// `droidsaw_dex::mutf8` fallback. Undecodable input degrades to lossy UTF-8
/// exactly like the old code did; the structured scanner never calls this.
#[allow(dead_code)]
pub(super) fn decode_lossy_string(data: &[u8]) -> String {
    match decode(data) {
        Ok(units) => String::from_utf16(&units)
            .unwrap_or_else(|_| String::from_utf8_lossy(data).into_owned()),
        Err(_) => String::from_utf8_lossy(data).into_owned(),
    }
}

/// MUTF-8 encoding for query text (kept for the legacy byte-matching path).
#[allow(dead_code)]
pub(super) fn encode_mutf8(value: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for unit in value.encode_utf16() {
        match unit {
            0 => out.extend_from_slice(&[0xc0, 0x80]),
            0x0001..=0x007f => out.push(unit as u8),
            0x0080..=0x07ff => {
                out.push((0xc0 | (unit >> 6)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
            _ => {
                out.push((0xe0 | (unit >> 12)) as u8);
                out.push((0x80 | ((unit >> 6) & 0x3f)) as u8);
                out.push((0x80 | (unit & 0x3f)) as u8);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The decoder boundary table: every accepted and rejected byte pattern.
    #[test]
    fn decode_accepts_and_rejects_the_documented_boundaries() {
        type DecodeCase = (&'static [u8], Result<Vec<u16>, DecodeError>);
        let cases: &[DecodeCase] = &[
            // Plain ASCII passes through one unit per byte.
            (&b"tok"[..], Ok(vec![0x74, 0x6f, 0x6b])),
            // NUL only exists as the two-byte form.
            (&[0x61, 0xc0, 0x80, 0x62][..], Ok(vec![0x61, 0x00, 0x62])),
            // Two-byte BMP.
            (&[0xc2, 0x80][..], Ok(vec![0x0080])),
            (&[0xc3, 0xa9][..], Ok(vec![0x00e9])),
            // Three-byte BMP, including the surrogate range MUTF-8 allows.
            (&[0xe0, 0xa0, 0x80][..], Ok(vec![0x0800])),
            (&[0xed, 0xa0, 0x80][..], Ok(vec![0xd800])),
            (&[0xed, 0xb0, 0x80][..], Ok(vec![0xdc00])),
            // A supplementary character is a surrogate pair of 3-byte forms.
            (
                &[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80][..],
                Ok(vec![0xd83d, 0xde00]),
            ),
            // Errors: overlong / wrong-tag bytes.
            (
                &[0xc0, 0x81][..],
                Err(DecodeError::IllegalContinuation(0x81)),
            ),
            (&[0xc1, 0x80][..], Err(DecodeError::IllegalLead(0xc1))),
            (&[0x80][..], Err(DecodeError::IllegalLead(0x80))),
            (&[0xbf][..], Err(DecodeError::IllegalLead(0xbf))),
            (
                &[0xf0, 0x90, 0x80, 0x80][..],
                Err(DecodeError::IllegalLead(0xf0)),
            ),
            (&[0xff][..], Err(DecodeError::IllegalLead(0xff))),
            (
                &[0xe0, 0x41, 0x80][..],
                Err(DecodeError::IllegalContinuation(0x41)),
            ),
            (
                &[0xc2, 0x00][..],
                Err(DecodeError::IllegalContinuation(0x00)),
            ),
            // Truncated sequences.
            (&[0xc2][..], Err(DecodeError::Truncated)),
            (&[0xe0][..], Err(DecodeError::Truncated)),
            (&[0xe0, 0x80][..], Err(DecodeError::Truncated)),
            (&[0xc0][..], Err(DecodeError::Truncated)),
        ];
        for (input, expected) in cases {
            let expected = expected.clone();
            match (decode(input), expected) {
                (Ok(actual), Ok(expected)) => assert_eq!(actual, expected, "input {input:?}"),
                (Err(actual), Err(expected)) => assert_eq!(actual, expected, "input {input:?}"),
                (actual, expected) => panic!("input {input:?}: got {actual:?}, want {expected:?}"),
            }
        }
        assert_eq!(decode(&[]).unwrap(), Vec::<u16>::new());
    }

    #[test]
    fn decode_into_reuses_the_buffer() {
        let mut scratch = vec![0xffff, 0xffff];
        decode_into(b"ab", &mut scratch).unwrap();
        assert_eq!(scratch, vec![0x61, 0x62]);
        decode_into(b"c", &mut scratch).unwrap();
        assert_eq!(scratch, vec![0x63]);
    }

    /// The string_data reading rule: decode exactly the declared unit count,
    /// never reading past it, and surface a raw terminator or short payload
    /// as errors instead of replacement output.
    #[test]
    fn decode_units_stops_at_the_declared_count() {
        let mut scratch = Vec::new();
        // Exactly the declared units; the caller checks the NUL afterwards.
        assert_eq!(decode_units(b"cat\0rest", 3, &mut scratch).unwrap(), 3);
        assert_eq!(scratch, vec![0x63, 0x61, 0x74]);
        // An empty string consumes nothing.
        assert_eq!(decode_units(b"\0", 0, &mut scratch).unwrap(), 0);
        assert!(scratch.is_empty());
        // The raw terminator arriving before the declared count.
        assert_eq!(
            decode_units(b"ab\0", 5, &mut scratch),
            Err(DecodeError::Terminator)
        );
        // A payload cut short by the end of the data.
        assert_eq!(
            decode_units(b"ca", 3, &mut scratch),
            Err(DecodeError::Truncated)
        );
        // Multi-byte units count one unit per sequence.
        assert_eq!(
            decode_units(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80, 0x00], 2, &mut scratch).unwrap(),
            6
        );
        assert_eq!(scratch, vec![0xd83d, 0xde00]);
    }

    #[test]
    fn encode_round_trips_through_decode() {
        for text in ["A\0Z", "é😀ok", "tok(en|x)", "\u{0001}\u{007f}"] {
            let encoded = encode_mutf8(text);
            let units = decode(&encoded).unwrap_or_else(|error| panic!("{text:?}: {error:?}"));
            assert_eq!(
                &units,
                &text.encode_utf16().collect::<Vec<u16>>(),
                "{text:?}"
            );
            assert_eq!(decode_lossy_string(&encoded), text);
        }
        // A stray NUL inside the payload is data, not a terminator: callers
        // split on the raw 0x00 byte before decoding.
        assert_eq!(encode_mutf8("a\0b"), b"a\xc0\x80b");
    }
}
