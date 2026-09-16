//! Allocation-free census of the structures the checked DEX parser owns.
//!
//! Counts follow referenced offsets, not `file_size * longest_string`. Shared
//! on-disk objects can be counted repeatedly (conservative); strings are
//! charged per owned alias. Container payload and geometric Vec spare capacity
//! are covered; allocator headers and BTree node padding are not RSS promises.
use crate::{
    analysis::BackendError, annotation::*, decode::*, header::DexHeader, ids::*, parser::DexFile,
};
use std::mem::size_of;

#[derive(Debug)]
enum WalkError {
    Malformed,
    Budget(BackendError),
}
type Walk<T> = Result<T, WalkError>;
struct Census<'a> {
    data: &'a [u8],
    header: DexHeader,
    bytes: u64,
}

impl Census<'_> {
    fn add(&mut self, count: u64, width: usize) -> Walk<()> {
        let bytes = count
            .checked_mul(width as u64)
            .and_then(|n| n.checked_add(self.bytes))
            .ok_or(WalkError::Budget(BackendError::MemoryBoundOverflow {
                label: "parser structure census",
            }))?;
        self.bytes = bytes;
        Ok(())
    }
    fn slots<T>(&mut self, count: u64) -> Walk<()> {
        // Vec growth is geometric. Four slots also cover Vec's initial floor.
        self.add(count.max(4), size_of::<T>().saturating_mul(2))
    }
    fn byte(&self, p: &mut usize) -> Walk<u8> {
        let b = *self.data.get(*p).ok_or(WalkError::Malformed)?;
        *p += 1;
        Ok(b)
    }
    fn u16(&self, p: usize) -> Walk<u16> {
        let bytes = self
            .data
            .get(p..p.checked_add(2).ok_or(WalkError::Malformed)?)
            .ok_or(WalkError::Malformed)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn u32(&self, p: usize) -> Walk<u32> {
        let bytes = self
            .data
            .get(p..p.checked_add(4).ok_or(WalkError::Malformed)?)
            .ok_or(WalkError::Malformed)?;
        Ok(u32::from_le_bytes(
            bytes.try_into().map_err(|_| WalkError::Malformed)?,
        ))
    }
    fn uleb(&self, p: &mut usize) -> Walk<u32> {
        let (v, n) = crate::mutf8::read_uleb128(self.data, *p).map_err(|_| WalkError::Malformed)?;
        *p = p.checked_add(n).ok_or(WalkError::Malformed)?;
        Ok(v)
    }
    fn sleb(&self, p: &mut usize) -> Walk<i32> {
        let (v, n) = crate::mutf8::read_sleb128(self.data, *p).map_err(|_| WalkError::Malformed)?;
        *p = p.checked_add(n).ok_or(WalkError::Malformed)?;
        Ok(v)
    }
    fn bounded(&self, n: u32, stride: usize) -> Walk<u64> {
        if n as u64 > (self.data.len() / stride) as u64 {
            return Err(WalkError::Malformed);
        }
        Ok(n as u64)
    }
    fn tolerant(&mut self, result: Walk<()>) -> Walk<()> {
        match result {
            Err(WalkError::Malformed) => self.slots::<crate::parser::ParseFailure>(1),
            other => other,
        }
    }
    fn string_bytes(&self, index: u32) -> u64 {
        if index >= self.header.string_ids_size {
            return 0;
        }
        let offset = self
            .u32(self.header.string_ids_off as usize + index as usize * 4)
            .unwrap_or(0);
        self.raw_string_bytes(offset).saturating_mul(3)
    }
    fn raw_string_bytes(&self, offset: u32) -> u64 {
        let mut p = offset as usize;
        if self.uleb(&mut p).is_err() {
            return 0;
        }
        self.data
            .get(p..)
            .map(|bytes| bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len()) as u64)
            .unwrap_or(0)
    }
    fn type_bytes(&self, index: u32) -> u64 {
        if index >= self.header.type_ids_size {
            return 0;
        }
        self.u32(self.header.type_ids_off as usize + index as usize * 4)
            .map(|id| self.string_bytes(id))
            .unwrap_or(0)
    }
    fn type_list(&mut self, offset: u32) -> Walk<()> {
        if offset == 0 {
            return Ok(());
        }
        let n = self.bounded(self.u32(offset as usize)?, 2)?;
        self.add(1, size_of::<(u32, Vec<TypeIdx>)>())?;
        self.slots::<TypeIdx>(n)
    }
    fn annotation_set(&mut self, offset: u32, references: bool) -> Walk<()> {
        if offset == 0 {
            return Ok(());
        }
        let base = offset as usize;
        let n = self.bounded(self.u32(base)?, 4)?;
        self.add(1, size_of::<(u32, Vec<u32>)>())?;
        // Persistent entries plus the pending traversal and cloned entries.
        self.slots::<u32>(n.checked_mul(3).ok_or(WalkError::Malformed)?)?;
        for index in 0..n {
            let off = self.u32(base + 4 + index as usize * 4)?;
            if off == 0 {
                continue;
            }
            let result = if references {
                self.annotation_set(off, false)
            } else {
                (|| {
                    self.add(1, size_of::<(u32, AnnotationItem)>())?;
                    let mut p = off as usize;
                    self.byte(&mut p)?;
                    self.annotation(&mut p, 0)
                })()
            };
            self.tolerant(result)?;
        }
        Ok(())
    }
    fn annotation_directory(&mut self, offset: u32) -> Walk<()> {
        if offset == 0 {
            return Ok(());
        }
        let base = offset as usize;
        let class = self.u32(base)?;
        let fields = self.bounded(self.u32(base + 4)?, 8)?;
        let methods = self.bounded(self.u32(base + 8)?, 8)?;
        let parameters = self.bounded(self.u32(base + 12)?, 8)?;
        self.add(1, size_of::<(u32, AnnotationDirectoryItem)>())?;
        self.slots::<FieldAnnotation>(fields)?;
        self.slots::<MethodAnnotation>(methods)?;
        self.slots::<ParameterAnnotation>(parameters)?;
        let result = self.annotation_set(class, false);
        self.tolerant(result)?;
        for index in 0..fields + methods + parameters {
            let off = self.u32(base + 16 + index as usize * 8 + 4)?;
            let result = self.annotation_set(off, index >= fields + methods);
            self.tolerant(result)?;
        }
        Ok(())
    }
    fn depth(&self, depth: usize) -> Walk<()> {
        // The census uses the Rust stack, unlike the parser's heap walker.
        // Refuse deeply nested inputs before either walk allocates their tree.
        if depth > 128 {
            return Err(WalkError::Budget(BackendError::MemoryBudget {
                bytes: u64::MAX,
                label: "parser annotation depth exceeds 128",
            }));
        }
        Ok(())
    }
    fn annotation(&mut self, p: &mut usize, depth: usize) -> Walk<()> {
        self.depth(depth)?;
        self.uleb(p)?;
        let n = self.bounded(self.uleb(p)?, 2)?;
        self.slots::<(StringIdx, EncodedValue)>(n)?;
        // Nested collector and deep-width traversal frames live together.
        self.add(2, size_of::<EncodedAnnotation>() + size_of::<usize>() * 4)?;
        for _ in 0..n {
            self.uleb(p)?;
            self.value(p, depth + 1)?;
        }
        Ok(())
    }
    fn array(&mut self, p: &mut usize, depth: usize) -> Walk<()> {
        self.depth(depth)?;
        let n = self.bounded(self.uleb(p)?, 1)?;
        self.slots::<EncodedValue>(n)?;
        // Both flat and recursive width tables can coexist.
        self.slots::<u8>(n.saturating_mul(2))?;
        self.add(2, size_of::<Vec<EncodedValue>>() + size_of::<usize>() * 4)?;
        for _ in 0..n {
            self.value(p, depth + 1)?;
        }
        Ok(())
    }
    fn value(&mut self, p: &mut usize, depth: usize) -> Walk<()> {
        self.depth(depth)?;
        let tag = self.byte(p)?;
        self.slots::<u8>(1)?;
        match tag & 0x1f {
            0x1c => self.array(p, depth),
            0x1d => self.annotation(p, depth),
            0x1e | 0x1f => Ok(()),
            _ => {
                *p = p
                    .checked_add(usize::from(tag >> 5) + 1)
                    .ok_or(WalkError::Malformed)?;
                if *p > self.data.len() {
                    Err(WalkError::Malformed)
                } else {
                    Ok(())
                }
            }
        }
    }
    fn encoded_array(&mut self, offset: u32) -> Walk<()> {
        if offset == 0 {
            return Ok(());
        }
        self.add(1, size_of::<(u32, Vec<EncodedValue>)>())?;
        self.array(&mut (offset as usize), 0)
    }
    fn debug(&mut self, offset: u32, decoded: bool) -> Walk<usize> {
        if offset == 0 {
            return Ok(0);
        }
        let start = offset as usize;
        let mut p = start;
        self.uleb(&mut p)?;
        let n = self.bounded(self.uleb(&mut p)?, 1)?;
        self.add(1, size_of::<(u32, crate::debug::DebugInfo)>())?;
        self.slots::<Option<String>>(n)?;
        for _ in 0..n {
            let id = self.uleb(&mut p)?;
            if decoded && id != 0 {
                self.add(self.string_bytes(id - 1), 1)?;
            }
        }
        let mut longest_name = 0;
        let mut longest_type = 0;
        self.slots::<(u32, u32)>(1)?;
        loop {
            let op = self.byte(&mut p)?;
            match op {
                0 => break,
                1 => {
                    self.uleb(&mut p)?;
                }
                2 => {
                    self.sleb(&mut p)?;
                    self.slots::<(u32, u32)>(1)?;
                }
                3 | 4 => {
                    self.uleb(&mut p)?;
                    let name = self.uleb(&mut p)?;
                    let typ = self.uleb(&mut p)?;
                    if op == 4 {
                        self.uleb(&mut p)?;
                    }
                    if decoded {
                        let nb = if name == 0 {
                            0
                        } else {
                            self.string_bytes(name - 1)
                        };
                        let tb = if typ == 0 {
                            0
                        } else {
                            self.type_bytes(typ - 1)
                        };
                        longest_name = longest_name.max(nb);
                        longest_type = longest_type.max(tb);
                        self.add(nb, 1)?;
                        self.add(tb, 1)?;
                        self.slots::<crate::debug::LocalVar>(1)?;
                        self.add(1, size_of::<(u16, crate::debug::LocalVar)>())?;
                    }
                }
                5 => {
                    self.uleb(&mut p)?;
                }
                6 => {
                    self.uleb(&mut p)?;
                    if decoded {
                        self.add(longest_name, 1)?;
                        self.add(longest_type, 1)?;
                        self.slots::<crate::debug::LocalVar>(1)?;
                        self.add(1, size_of::<(u16, crate::debug::LocalVar)>())?;
                    }
                }
                7 | 8 => (),
                9 => {
                    self.uleb(&mut p)?;
                }
                _ => self.slots::<(u32, u32)>(1)?,
            }
        }
        self.add((p - start) as u64, 1)?;
        self.add(1, size_of::<(u32, Vec<u8>)>())?;
        Ok(p)
    }
    fn payload(&mut self, base: usize) -> Walk<usize> {
        let ident = self.u16(base)?;
        self.add(1, size_of::<(u32, PayloadData)>())?;
        let length = match ident {
            0x0100 => {
                let n = self.u16(base + 2)? as u64;
                self.slots::<u32>(n)?;
                8 + n * 4
            }
            0x0200 => {
                let n = self.u16(base + 2)? as u64;
                self.slots::<u32>(n)?;
                self.slots::<i32>(n)?;
                4 + n * 8
            }
            0x0300 => {
                let n = self.u32(base + 4)? as u64 * self.u16(base + 2)? as u64;
                self.add(n, 1)?;
                8 + n.div_ceil(2) * 2
            }
            _ => return Err(WalkError::Malformed),
        };
        usize::try_from(length).map_err(|_| WalkError::Malformed)
    }
    fn code(&mut self, offset: u32) -> Walk<()> {
        if offset == 0 {
            return Ok(());
        }
        let base = offset as usize;
        let tries = self.u16(base + 6)? as u64;
        let debug = self.u32(base + 8)?;
        let units = self.u32(base + 12)? as usize;
        let start = base + 16;
        let end = start
            .checked_add(units.checked_mul(2).ok_or(WalkError::Malformed)?)
            .ok_or(WalkError::Malformed)?;
        if end > self.data.len() {
            return Err(WalkError::Malformed);
        }
        self.add(1, size_of::<(u32, CodeItem)>())?;
        let mut p = start;
        while p < end {
            let word = self.u16(p)?;
            if matches!(word, 0x0100 | 0x0200 | 0x0300) {
                let len = self.payload(p)?;
                p = p.checked_add(len).ok_or(WalkError::Malformed)?;
                continue;
            }
            // opcode starts and the post-decode pc->opcode map are independent.
            self.add(
                1,
                size_of::<(u32, ())>() + size_of::<(u32, crate::opcodes::Opcode)>(),
            )?;
            self.slots::<Instruction>(1)?;
            // Register, branch and payload invariant records: no more than
            // five source registers, one destination and two address checks.
            self.slots::<CodeItemInvariantViolation>(8)?;
            let byte = word as u8;
            if matches!(byte, 0x26 | 0x2b | 0x2c) {
                self.slots::<(u32, u32, crate::opcodes::Opcode)>(1)?;
                if let Ok(relative) = self.u32(p + 2) {
                    let target = (p as i64) + (relative as i32 as i64) * 2;
                    if let Ok(target) = usize::try_from(target) {
                        let result = self.payload(target).map(|_| ());
                        self.tolerant(result)?;
                    }
                }
            }
            let width = crate::opcodes::Opcode::from_u8(byte)
                .map(|op| crate::decode::format_size(crate::decode::insn_format(op)) as usize)
                .unwrap_or(1);
            p = p.checked_add(width * 2).ok_or(WalkError::Malformed)?;
        }
        self.slots::<TryItem>(tries)?;
        self.slots::<CodeItemInvariantViolation>(tries + 2)?;
        if tries > 0 {
            let mut p = end + (units % 2) * 2 + (tries as usize) * 8;
            let count = self.bounded(self.uleb(&mut p)?, 1)?;
            self.slots::<CatchHandler>(count)?;
            self.add(count, size_of::<(u32, usize)>())?;
            for _ in 0..count {
                let n = self.sleb(&mut p)?;
                let catches = self.bounded(n.unsigned_abs(), 2)?;
                self.slots::<TypedCatch>(catches)?;
                for _ in 0..catches {
                    self.uleb(&mut p)?;
                    self.uleb(&mut p)?;
                }
                if n <= 0 {
                    self.uleb(&mut p)?;
                }
            }
        }
        let result = self.debug(debug, true).map(|_| ());
        self.tolerant(result)
    }
    fn class_data(&mut self, offset: u32) -> Walk<()> {
        if offset == 0 {
            return Ok(());
        }
        let mut p = offset as usize;
        let sf = self.bounded(self.uleb(&mut p)?, 2)?;
        let inf = self.bounded(self.uleb(&mut p)?, 2)?;
        let dm = self.bounded(self.uleb(&mut p)?, 3)?;
        let vm = self.bounded(self.uleb(&mut p)?, 3)?;
        self.add(1, size_of::<(u32, ClassData)>())?;
        self.slots::<EncodedField>(sf + inf)?;
        self.slots::<EncodedMethod>(dm + vm)?;
        for _ in 0..sf + inf {
            self.uleb(&mut p)?;
            self.uleb(&mut p)?;
        }
        for _ in 0..dm + vm {
            self.uleb(&mut p)?;
            self.uleb(&mut p)?;
            let code = self.uleb(&mut p)?;
            let result = self.code(code);
            self.tolerant(result)?;
        }
        self.add((p - offset as usize) as u64, 1)?;
        self.add(1, size_of::<(u32, Vec<u8>)>())
    }
    fn run(&mut self) -> Walk<()> {
        self.add(1, size_of::<DexFile>())?;
        self.slots::<crate::DexString>(self.header.string_ids_size as u64)?;
        self.slots::<u32>(self.header.string_ids_size as u64)?;
        self.slots::<Result<(crate::DexString, u32), crate::error::DexError>>(
            self.header.string_ids_size as u64,
        )?;
        self.slots::<String>(self.header.type_ids_size as u64)?;
        self.slots::<StringIdx>(self.header.type_ids_size as u64)?;
        self.slots::<Option<usize>>(self.header.type_ids_size as u64)?;
        self.slots::<ProtoIdItem>(self.header.proto_ids_size as u64)?;
        self.slots::<FieldIdItem>(self.header.field_ids_size as u64)?;
        self.slots::<MethodIdItem>(self.header.method_ids_size as u64)?;
        self.slots::<ClassDefItem>(self.header.class_defs_size as u64)?;
        // Pool ordering violations: at most one finding per adjacent pair.
        let ids = self.header.string_ids_size as u64
            + self.header.type_ids_size as u64
            + self.header.proto_ids_size as u64
            + self.header.field_ids_size as u64
            + self.header.method_ids_size as u64
            + self.header.class_defs_size as u64;
        self.slots::<crate::parser::ParseFailure>(ids)?;
        for index in 0..self.header.string_ids_size {
            let offset = self.u32(self.header.string_ids_off as usize + index as usize * 4)?;
            let raw = self.raw_string_bytes(offset);
            // Raw MUTF-8, decoded/lossy UTF-8 (<=3 bytes per raw byte),
            // plus the decoder's UTF-16 temporary (<=2 bytes per raw byte).
            self.add(raw, 1 + 3 + 2)?;
        }
        for index in 0..self.header.type_ids_size {
            self.add(self.type_bytes(index), 1)?;
        }
        for index in 0..self.header.proto_ids_size {
            let off = self.u32(self.header.proto_ids_off as usize + index as usize * 12 + 8)?;
            let result = self.type_list(off);
            self.tolerant(result)?;
        }
        for index in 0..self.header.class_defs_size {
            let p = self.header.class_defs_off as usize + index as usize * 32;
            let result = self.type_list(self.u32(p + 12)?);
            self.tolerant(result)?;
            let result = self.annotation_directory(self.u32(p + 20)?);
            self.tolerant(result)?;
            let result = self.class_data(self.u32(p + 24)?);
            self.tolerant(result)?;
            let result = self.encoded_array(self.u32(p + 28)?);
            self.tolerant(result)?;
        }
        if self.header.map_off != 0 {
            let base = self.header.map_off as usize;
            let count = self.bounded(self.u32(base)?, 12)?;
            // map-driven parse and the retained map table both exist.
            self.slots::<crate::parser::MapEntry>(count * 2)?;
            for index in 0..count {
                let p = base + 4 + index as usize * 12;
                let kind = self.u16(p)?;
                let n = self.u32(p + 4)?;
                let offset = self.u32(p + 8)?;
                match kind {
                    0x0007 => {
                        self.slots::<u32>(self.bounded(n, 4)?)?;
                        for i in 0..n {
                            let off = self.u32(offset as usize + i as usize * 4)?;
                            let result = self.encoded_array(off);
                            self.tolerant(result)?;
                        }
                    }
                    0x0008 => self.slots::<crate::parser::MethodHandleItem>(self.bounded(n, 8)?)?,
                    0x2003 => {
                        // Orphan debug entries retain raw bytes, not decoded locals.
                        let mut cursor = offset;
                        self.slots::<crate::parser::SectionRegion>(self.bounded(n, 1)? + 1)?;
                        for _ in 0..n {
                            match self.debug(cursor, false) {
                                Ok(end) if end > cursor as usize => {
                                    cursor = u32::try_from(end).map_err(|_| WalkError::Malformed)?
                                }
                                Err(WalkError::Budget(error)) => {
                                    return Err(WalkError::Budget(error));
                                }
                                _ => break,
                            }
                        }
                    }
                    0x1003 => {
                        self.slots::<crate::parser::SectionRegion>(self.bounded(n, 4)? + 1)?;
                        let mut cursor = offset as usize;
                        for _ in 0..n {
                            let entries = self.bounded(self.u32(cursor)?, 4)?;
                            self.slots::<u32>(entries)?;
                            self.add(1, size_of::<(u32, Vec<u32>)>())?;
                            cursor = cursor
                                .checked_add(4 + entries as usize * 4)
                                .ok_or(WalkError::Malformed)?;
                        }
                    }
                    _ => (),
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn parser_bound(data: &[u8]) -> Result<u64, BackendError> {
    let header = DexHeader::parse(data)?;
    let mut census = Census {
        data,
        header,
        bytes: 0,
    };
    match census.run() {
        Ok(()) | Err(WalkError::Malformed) => Ok(census.bytes),
        Err(WalkError::Budget(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const DEX: &[u8] = include_bytes!("../tests/fixtures/g02-static-initializers.dex");

    #[test]
    fn tiny_fixture_has_a_finite_structural_bound() {
        let bytes = parser_bound(DEX).unwrap();
        assert!(bytes > DEX.len() as u64);
        assert!(bytes < 1024 * 1024, "tiny DEX estimated at {bytes} bytes");
    }

    #[test]
    fn large_unused_string_does_not_multiply_all_debug_storage() {
        let baseline = parser_bound(DEX).unwrap();
        let header = DexHeader::parse(DEX).unwrap();
        let mut bytes = DEX.to_vec();
        let offset = bytes.len() as u32;
        // 65,536 UTF-16 units, all ASCII, referenced by one pool slot.
        bytes.extend_from_slice(&[0x80, 0x80, 0x04]);
        bytes.extend(std::iter::repeat_n(b'x', 65_536));
        bytes.push(0);
        let slot = header.string_ids_off as usize + (header.string_ids_size as usize - 1) * 4;
        bytes[slot..slot + 4].copy_from_slice(&offset.to_le_bytes());
        let len = bytes.len() as u32;
        bytes[32..36].copy_from_slice(&len.to_le_bytes());
        bytes[104..108].copy_from_slice(&(len - header.data_off).to_le_bytes());
        let bound = parser_bound(&bytes).unwrap();
        assert!(bound > baseline + 65_536);
        assert!(
            bound < baseline + 4 * 1024 * 1024,
            "unused string amplified unrelated state: {bound}"
        );
    }

    #[test]
    fn excessive_nested_annotation_is_refused_before_tree_allocation() {
        let mut bytes = Vec::new();
        for _ in 0..140 {
            bytes.extend_from_slice(&[1, 0x1c]);
        }
        bytes.push(0);
        let mut census = Census {
            data: &bytes,
            header: DexHeader::parse(DEX).unwrap(),
            bytes: 0,
        };
        let error = census.array(&mut 0, 0).unwrap_err();
        assert!(matches!(
            error,
            WalkError::Budget(BackendError::MemoryBudget {
                label: "parser annotation depth exceeds 128",
                ..
            })
        ));
    }

    #[test]
    fn structural_arithmetic_overflow_is_typed() {
        let mut census = Census {
            data: DEX,
            header: DexHeader::parse(DEX).unwrap(),
            bytes: u64::MAX,
        };
        assert!(matches!(
            census.add(1, 1),
            Err(WalkError::Budget(BackendError::MemoryBoundOverflow { .. }))
        ));
    }
}
