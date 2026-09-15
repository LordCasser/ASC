//! Bounds-checked little-endian cursor over the input bytes.
//!
//! Every read returns a `ParseError` instead of panicking; all arithmetic is
//! done in `usize` with checked operations so declared chunk sizes can never
//! wrap around the buffer.

use crate::ParseError;

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

fn malformed(at: usize, what: &str) -> ParseError {
    ParseError::Malformed(format!("{what} at byte offset {at}"))
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// The current byte position.
    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn seek(&mut self, pos: usize) -> Result<(), ParseError> {
        if pos > self.data.len() {
            return Err(malformed(self.pos, "seek past the end of the input"));
        }
        self.pos = pos;
        Ok(())
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ParseError> {
        let bytes = self
            .data
            .get(self.pos..self.pos + 2)
            .ok_or_else(|| malformed(self.pos, "truncated read (u16)"))?;
        self.pos += 2;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ParseError> {
        let bytes = self
            .data
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| malformed(self.pos, "truncated read (u32)"))?;
        self.pos += 4;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// `count` bytes starting at the cursor; advances it.
    pub(crate) fn bytes(&mut self, count: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or_else(|| malformed(self.pos, "length overflow"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| malformed(self.pos, "truncated byte run"))?;
        self.pos = end;
        Ok(slice)
    }
}
