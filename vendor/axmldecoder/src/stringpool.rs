//! Validating reader for the AXML string pool (AX-P01/AX-P04).
//!
//! Decodes both UTF-16 and UTF-8 pools including the two-byte extended length
//! forms, keeps style spans as metadata with boundary validation, and turns
//! every inconsistency (offsets outside the pool, lengths crossing the chunk
//! end, invalid UTF-8/UTF-16, oversized strings) into a `ParseError`.

use crate::cursor::Cursor;
use crate::ParseError;

/// Sentinel used for "no string" indices throughout binary XML.
pub(crate) const NO_INDEX: u32 = 0xFFFF_FFFF;

/// One style span attached to a pool string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StyleSpan {
    /// Index into the pool's own string table naming the span (a tag name).
    pub name: u32,
    /// First UTF-16 unit the span applies to.
    pub first_char: u32,
    /// One past the last UTF-16 unit the span applies to.
    pub last_char: u32,
}

/// The decoded string pool. Strings are validated Unicode; styles survive as
/// structured metadata and are never rendered here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StringPoolData {
    pub strings: Vec<String>,
    /// `styles[i]` holds the spans of string `i`; indices are into `strings`.
    pub styles: Vec<(u32, Vec<StyleSpan>)>,
    pub is_utf8: bool,
}

impl StringPoolData {
    /// Resolved string for an index, or `None` for the sentinel index.
    pub(crate) fn get(&self, index: u32) -> Option<&str> {
        if index == NO_INDEX {
            return None;
        }
        self.strings.get(index as usize).map(String::as_str)
    }

    pub(crate) fn require(&self, index: u32, what: &str) -> Result<String, ParseError> {
        match self.get(index) {
            Some(text) => Ok(text.to_owned()),
            None => Err(ParseError::Malformed(format!(
                "{what} references string index {index} outside the pool ({} strings)",
                self.strings.len()
            ))),
        }
    }
}

/// Reads the string-pool chunk starting at `offset`; returns the data and the
/// chunk's total size.
pub(crate) fn read_string_pool(
    data: &[u8],
    offset: usize,
    max_string_units: usize,
) -> Result<(StringPoolData, usize), ParseError> {
    const STRING_POOL_TYPE: u16 = 0x0001;
    const FLAG_UTF8: u32 = 1 << 8;
    const FLAG_SORTED: u32 = 1 << 0;
    const HEADER_FIELDS: usize = 28; // chunk header (8) + five u32 fields

    let mut cursor = Cursor::new(data);
    cursor.seek(offset)?;

    let chunk_type = cursor.u16()?;
    let header_size = cursor.u16()?;
    let chunk_size = cursor.u32()? as usize;
    let string_count = cursor.u32()?;
    let style_count = cursor.u32()?;
    let flags = cursor.u32()?;
    let strings_start = cursor.u32()? as usize;
    let styles_start = cursor.u32()? as usize;

    if chunk_type != STRING_POOL_TYPE {
        return Err(ParseError::Malformed(format!(
            "expected a string pool chunk (0x0001) at offset {offset}, found 0x{chunk_type:04X}"
        )));
    }
    let chunk_end = offset
        .checked_add(chunk_size)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| {
            ParseError::Malformed(format!(
                "string pool at offset {offset} declares {chunk_size} bytes, past the input end"
            ))
        })?;
    if usize::from(header_size) < HEADER_FIELDS {
        return Err(ParseError::Malformed(format!(
            "string pool header size {header_size} cannot hold its own fields"
        )));
    }
    if usize::from(header_size) > chunk_size {
        return Err(ParseError::Malformed(format!(
            "string pool header size {header_size} exceeds its chunk size {chunk_size}"
        )));
    }
    if flags & !(FLAG_UTF8 | FLAG_SORTED) != 0 {
        return Err(ParseError::Malformed(format!(
            "string pool sets unknown flags 0x{flags:08X}"
        )));
    }
    let is_utf8 = flags & FLAG_UTF8 != 0;

    // The offsets arrays sit between the header and the string data:
    // string_count string offsets followed by style_count style offsets.
    let offsets_end = usize::from(header_size)
        .checked_add(
            string_count
                .checked_add(style_count)
                .and_then(|n| usize::try_from(n).ok())
                .and_then(|n| n.checked_mul(4))
                .ok_or_else(|| ParseError::Malformed("string pool counts overflow".to_owned()))?,
        )
        .ok_or_else(|| ParseError::Malformed("string pool counts overflow".to_owned()))?;
    // Offsets are relative to the chunk start.
    if offsets_end > strings_start || strings_start > chunk_size {
        return Err(ParseError::Malformed(format!(
            "string pool offsets array (ends at {offsets_end}) does not fit before the \
             string data (starts at {strings_start}, chunk ends at {chunk_end})"
        )));
    }
    if style_count > 0 && (styles_start < strings_start || styles_start > chunk_size) {
        return Err(ParseError::Malformed(format!(
            "string pool styles start {styles_start} is outside the chunk"
        )));
    }

    let string_offsets = read_offset_array(data, offset + usize::from(header_size), string_count)?;
    let style_offsets = read_offset_array(
        data,
        offset + usize::from(header_size) + 4 * string_count as usize,
        style_count,
    )?;

    // `strings_start`/`styles_start` and the offset arrays' values are all
    // relative to the chunk start, while reads address the whole input.
    let region_end = if style_count > 0 {
        offset + styles_start
    } else {
        chunk_end
    };
    let mut strings = Vec::with_capacity(string_count as usize);
    let mut unit_counts = Vec::with_capacity(string_count as usize);
    for (i, rel) in string_offsets.iter().enumerate() {
        let absolute = offset
            .checked_add(strings_start)
            .and_then(|base| base.checked_add(*rel as usize))
            .ok_or_else(|| ParseError::Malformed(format!("string {i} offset overflows")))?;
        if absolute >= region_end {
            return Err(ParseError::Malformed(format!(
                "string {i} starts at {absolute}, outside the string data \
                 [{}, {region_end})",
                offset + strings_start
            )));
        }
        let (text, units) = if is_utf8 {
            parse_utf8_string(data, absolute, region_end)?
        } else {
            parse_utf16_string(data, absolute, region_end)?
        };
        if units > max_string_units {
            return Err(ParseError::Limit(format!(
                "string {i} has {units} UTF-16 units, above the limit of {max_string_units}"
            )));
        }
        strings.push(text);
        unit_counts.push(units as u32);
    }

    let mut styles = Vec::new();
    for (i, rel) in style_offsets.iter().enumerate() {
        let absolute = offset
            .checked_add(styles_start)
            .and_then(|base| base.checked_add(*rel as usize))
            .ok_or_else(|| ParseError::Malformed(format!("style {i} offset overflows")))?;
        if absolute >= chunk_end {
            return Err(ParseError::Malformed(format!(
                "style {i} starts at {absolute}, outside the style data [{}, {chunk_end})",
                offset + styles_start
            )));
        }
        let spans = parse_style_entry(data, absolute, chunk_end, string_count)?;
        // Validate span boundaries against the owning string. AOSP indexes the
        // styles array by string index, so entry i belongs to string i.
        if let Some(units) = unit_counts.get(i) {
            for span in &spans {
                if span.name >= string_count
                    || span.first_char > span.last_char
                    || span.last_char > *units
                {
                    return Err(ParseError::Malformed(format!(
                        "style {i} span (name {}, chars {}..{}) does not fit string {i} \
                         ({} units, {} strings)",
                        span.name, span.first_char, span.last_char, units, string_count
                    )));
                }
            }
        } else {
            return Err(ParseError::Malformed(format!(
                "style entry {i} has no owning string ({string_count} strings)"
            )));
        }
        if !spans.is_empty() {
            styles.push((i as u32, spans));
        }
    }

    Ok((StringPoolData { strings, styles, is_utf8 }, chunk_size))
}

fn read_offset_array(data: &[u8], at: usize, count: u32) -> Result<Vec<u32>, ParseError> {
    let mut cursor = Cursor::new(data);
    cursor.seek(at)?;
    let mut offsets = Vec::with_capacity(count as usize);
    for _ in 0..count {
        offsets.push(cursor.u32()?);
    }
    Ok(offsets)
}

/// One string length from a UTF-8 pool: one byte, or two when the high bit of
/// the first is set. Returns (length, bytes consumed).
fn decode_length_8(data: &[u8], at: usize, end: usize) -> Result<(usize, usize), ParseError> {
    let first = *data
        .get(at)
        .ok_or_else(|| ParseError::Malformed("truncated UTF-8 string length".to_owned()))?;
    if first & 0x80 == 0 {
        return Ok((usize::from(first), 1));
    }
    let second = *data
        .get(at + 1)
        .ok_or_else(|| ParseError::Malformed("truncated extended UTF-8 string length".to_owned()))?;
    let length = ((usize::from(first & 0x7f)) << 8) | usize::from(second);
    if at + 2 > end {
        return Err(ParseError::Malformed(
            "extended UTF-8 string length crosses the pool end".to_owned(),
        ));
    }
    Ok((length, 2))
}

/// One string length from a UTF-16 pool: one unit, or three units (one extra
/// length unit plus a marker) when the high bit of the first marks the
/// extended form.
fn decode_length_16(data: &[u8], at: usize, end: usize) -> Result<(usize, usize), ParseError> {
    let read_unit =
        |offset: usize| -> Result<u16, ParseError> {
            let bytes = data.get(offset..offset + 2).ok_or_else(|| {
                ParseError::Malformed("truncated UTF-16 string length".to_owned())
            })?;
            Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
        };
    let first = read_unit(at)?;
    if first & 0x8000 == 0 {
        return Ok((usize::from(first), 2));
    }
    let second = read_unit(at + 2)?;
    let length = ((usize::from(first & 0x7fff)) << 16) | usize::from(second);
    if at + 4 > end {
        return Err(ParseError::Malformed(
            "extended UTF-16 string length crosses the pool end".to_owned(),
        ));
    }
    Ok((length, 4))
}

fn parse_utf16_string(
    data: &[u8],
    at: usize,
    end: usize,
) -> Result<(String, usize), ParseError> {
    let (units, header) = decode_length_16(data, at, end)?;
    let byte_len = units
        .checked_mul(2)
        .ok_or_else(|| ParseError::Malformed("UTF-16 string length overflows".to_owned()))?;
    let text_end = at
        .checked_add(header)
        .and_then(|start| start.checked_add(byte_len))
        .ok_or_else(|| ParseError::Malformed("UTF-16 string length overflows".to_owned()))?;
    if text_end > end {
        return Err(ParseError::Malformed(format!(
            "UTF-16 string at {at} runs {units} units past the pool end {end}"
        )));
    }
    let mut units_buf = Vec::with_capacity(units);
    let mut cursor = Cursor::new(data);
    cursor.seek(at + header)?;
    for _ in 0..units {
        units_buf.push(cursor.u16()?);
    }
    let text = String::from_utf16(&units_buf).map_err(|_| {
        ParseError::Malformed(format!(
            "string at {at} is not valid UTF-16 (unpaired surrogate)"
        ))
    })?;
    Ok((text, units))
}

fn parse_utf8_string(data: &[u8], at: usize, end: usize) -> Result<(String, usize), ParseError> {
    let (char_len, header1) = decode_length_8(data, at, end)?;
    let (byte_len, header2) = decode_length_8(data, at + header1, end)?;
    let text_end = at
        .checked_add(header1)
        .and_then(|start| start.checked_add(header2))
        .and_then(|start| start.checked_add(byte_len))
        .ok_or_else(|| ParseError::Malformed("UTF-8 string length overflows".to_owned()))?;
    if text_end > end {
        return Err(ParseError::Malformed(format!(
            "UTF-8 string at {at} runs {byte_len} bytes past the pool end {end}"
        )));
    }
    let mut cursor = Cursor::new(data);
    cursor.seek(at + header1 + header2)?;
    let bytes = cursor.bytes(byte_len)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ParseError::Malformed(format!("string at {at} is not valid UTF-8")))?
        .to_owned();
    Ok((text, char_len))
}

/// One style entry: a run of spans terminated by the `0xFFFFFFFF` sentinel.
fn parse_style_entry(
    data: &[u8],
    at: usize,
    _end: usize,
    string_count: u32,
) -> Result<Vec<StyleSpan>, ParseError> {
    let mut cursor = Cursor::new(data);
    cursor.seek(at)?;
    let mut spans = Vec::new();
    loop {
        let name = cursor.u32()?;
        if name == NO_INDEX {
            return Ok(spans);
        }
        if name >= string_count {
            return Err(ParseError::Malformed(format!(
                "style span name index {name} is outside the string pool"
            )));
        }
        let first_char = cursor.u32()?;
        let last_char = cursor.u32()?;
        spans.push(StyleSpan { name, first_char, last_char });
    }
}
