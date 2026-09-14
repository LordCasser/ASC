//! Reference search manager and code item scanner.

use std::collections::{HashMap, HashSet};
use crate::core::tinydex::Dex;
use crate::core::findrefs::locator::{
    FieldLocator, InsnLocator, MethodIdxEntry, MethodLocator, StringLocator, TypeLocator,
};
use regex::bytes::Regex;

/// Helper to read little-endian u16 from slice
#[inline(always)]
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Helper to read little-endian u32 from slice
#[inline(always)]
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

// ---------------------------------------------------------------------------
// Query types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct MethodQuery<'a> {
    pub class: Option<(&'a str, bool)>, // (class_name, is_precise)
    pub method: Option<&'a str>,
}

#[derive(Clone, Debug, Default)]
pub struct FieldQuery<'a> {
    pub class: Option<(&'a str, bool)>, // (class_name, is_precise)
    pub field: Option<&'a str>,
}

#[derive(Clone, Debug, Default)]
pub struct FindQuery<'a> {
    pub string: Option<&'a str>,
    pub r#type: Option<&'a str>,
    pub method: Option<MethodQuery<'a>>,
    pub field: Option<FieldQuery<'a>>,
}

// ---------------------------------------------------------------------------
// CodeItemScanner
// ---------------------------------------------------------------------------

pub struct CodeItemScanner<'a> {
    pub insn_locator: &'a InsnLocator<'a>,
    pub off_start: usize,
    pub off_end: usize,
    pub mark_idx: Vec<u32>,
}

impl<'a> CodeItemScanner<'a> {
    pub fn new(insn_locator: &'a InsnLocator<'a>) -> Self {
        Self {
            insn_locator,
            off_start: insn_locator.code_item_start,
            off_end: insn_locator.code_item_end,
            mark_idx: Vec::new(),
        }
    }

    /// Dense scanner matching python's `_scan_code_item_dense`
    fn scan_code_item_dense(
        &mut self,
        opcode_values: &[u8],
        idxs: &HashSet<u32>,
        mark: bool,
        matched_offsets: &mut Vec<usize>,
    ) {
        let buf = self.insn_locator.dex.buf;
        let off_start = self.off_start;
        let off_end = self.off_end.min(buf.len());
        if off_start >= off_end {
            return;
        }

        let mut op_mask = [false; 256];
        for &op in opcode_values {
            op_mask[op as usize] = true;
        }

        let mut hi_mask = [false; 256];
        for &idx in idxs {
            hi_mask[((idx >> 8) & 0xFF) as usize] = true;
        }

        let len = off_end - off_start;
        let sub = &buf[off_start..off_end];

        // We check op at offset, and hi byte at offset + 3. So offset + 3 < len.
        if len < 4 {
            return;
        }

        for i in 0..(len - 3) {
            let op = sub[i];
            if op_mask[op as usize] {
                let hi = sub[i + 3];
                if hi_mask[hi as usize] {
                    let idx = read_u16(sub, i + 2) as u32;
                    if idxs.contains(&idx) {
                        matched_offsets.push(i + off_start);
                        if mark {
                            self.mark_idx.push(idx);
                        }
                    }
                }
            }
        }
    }

    /// Regex / fallback scanner for opcodes with idx lookahead
    fn scan_code_item_pattern(
        &mut self,
        opcode_values: &[u8],
        idx_width: usize,
        idxs: &HashSet<u32>,
        mark: bool,
        matched_offsets: &mut Vec<usize>,
    ) {
        let buf = self.insn_locator.dex.buf;
        let off_start = self.off_start;
        let off_end = self.off_end.min(buf.len());
        if off_start >= off_end {
            return;
        }
        let sub = &buf[off_start..off_end];

        // Build regex pattern matching opcode byte followed by 1 byte, then matching any byte that matches idx bytes
        // In Rust, for high performance:
        // We can create a regex `[opcodes](?=.[bytes0][bytes1]...)` or directly scan
        let mut byte_classes: Vec<HashSet<u8>> = Vec::new();
        for shift in (0..idx_width * 8).step_by(8) {
            let b_set: HashSet<u8> = idxs.iter().map(|&idx| ((idx >> shift) & 0xFF) as u8).collect();
            byte_classes.push(b_set);
        }

        // Build character class string
        fn build_class(set: &HashSet<u8>) -> String {
            let mut s = String::from("[");
            for &b in set {
                s.push_str(&format!("\\x{:02x}", b));
            }
            s.push(']');
            s
        }

        let op_class = {
            let mut s = String::from("[");
            for &op in opcode_values {
                s.push_str(&format!("\\x{:02x}", op));
            }
            s.push(']');
            s
        };

        let mut lookahead = String::from(".?");
        // Note: opcode is at offset 0, byte 1 is register/flags, byte 2 is first idx byte
        // In regex: (?=.[b0][b1])
        lookahead = String::from(".");
        for b_set in &byte_classes {
            lookahead.push_str(&build_class(b_set));
        }

        let pattern_str = format!("{}(?={})", op_class, lookahead);
        let pattern = match Regex::new(&pattern_str) {
            Ok(p) => p,
            Err(_) => return,
        };

        for m in pattern.find_iter(sub) {
            let start = m.start();
            if start + 2 + idx_width <= sub.len() {
                let idx = if idx_width == 4 {
                    read_u32(sub, start + 2)
                } else {
                    read_u16(sub, start + 2) as u32
                };

                if idxs.contains(&idx) {
                    matched_offsets.push(start + off_start);
                    if mark {
                        self.mark_idx.push(idx);
                    }
                }
            }
        }
    }

    pub fn scan_code_item(&mut self, kind: &str, idxs: &HashSet<u32>, mark: bool) -> Vec<usize> {
        self.mark_idx.clear();
        let mut matched_offsets = Vec::new();

        // Groups matching python `_IDX_GROUPS`:
        // "string" : ((b"\x1a", 2), (b"\x1b", 4))
        // "type"   : ((b"\x1c\x1f\x20\x22\x23\x24\x25", 2),)
        // "field"  : ((0x52..=0x6d, 2),)
        // "method" : ((0x6e..=0x72, 0x74..=0x78, 0xfa, 0xfb, 2),)
        match kind {
            "string" => {
                // (b"\x1a", 2) and (b"\x1b", 4)
                let mark_before = self.mark_idx.len();
                self.scan_code_item_pattern(&[0x1a], 2, idxs, mark, &mut matched_offsets);
                self.scan_code_item_pattern(&[0x1b], 4, idxs, mark, &mut matched_offsets);

                // Because there are two groups, restore offset order if needed
                let mut indices: Vec<usize> = (0..matched_offsets.len()).collect();
                indices.sort_by_key(|&i| matched_offsets[i]);
                matched_offsets = indices.iter().map(|&i| matched_offsets[i]).collect();
                if mark {
                    let mark_slice = &self.mark_idx[mark_before..];
                    let sorted_marks: Vec<u32> = indices.iter().map(|&i| mark_slice[i]).collect();
                    self.mark_idx.splice(mark_before.., sorted_marks);
                }
            }
            "type" => {
                let opcodes = [0x1c, 0x1f, 0x20, 0x22, 0x23, 0x24, 0x25];
                self.scan_code_item_dense(&opcodes, idxs, mark, &mut matched_offsets);
            }
            "field" => {
                let opcodes: Vec<u8> = (0x52..=0x6du8).collect();
                self.scan_code_item_dense(&opcodes, idxs, mark, &mut matched_offsets);
            }
            "method" => {
                let mut opcodes: Vec<u8> = Vec::new();
                opcodes.extend(0x6e..=0x72u8);
                opcodes.extend(0x74..=0x78u8);
                opcodes.push(0xfa);
                opcodes.push(0xfb);
                self.scan_code_item_dense(&opcodes, idxs, mark, &mut matched_offsets);
            }
            _ => {}
        }

        matched_offsets
    }

    pub fn scan(
        &mut self,
        target_map: &HashMap<String, HashSet<u32>>,
        mark: bool,
    ) -> HashMap<String, Vec<Option<MethodIdxEntry>>> {
        let mut results = HashMap::new();

        for (kind, idxs) in target_map {
            if idxs.is_empty() {
                results.insert(kind.clone(), Vec::new());
                continue;
            }

            let insn_offs = self.scan_code_item(kind, idxs, mark);
            let mids = self.insn_locator.locate(&insn_offs);
            results.insert(kind.clone(), mids);
        }

        results
    }
}

// ---------------------------------------------------------------------------
// FindRefManager
// ---------------------------------------------------------------------------

pub struct FindRefManager<'a> {
    pub dex: Dex<'a>,
    pub debug: bool,
    pub str_locator: Option<StringLocator<'a>>,
    pub type_locator: Option<TypeLocator<'a>>,
    pub method_locator: Option<MethodLocator<'a>>,
    pub field_locator: Option<FieldLocator<'a>>,
    pub insn_locator: Option<InsnLocator<'a>>,
    pub last_mark_idx: Vec<u32>,
}

impl<'a> FindRefManager<'a> {
    pub fn new(dex: Dex<'a>, debug: bool) -> Self {
        Self {
            dex,
            debug,
            str_locator: None,
            type_locator: None,
            method_locator: None,
            field_locator: None,
            insn_locator: None,
            last_mark_idx: Vec::new(),
        }
    }

    pub fn get_str_locator(&mut self, build: bool) -> &mut StringLocator<'a> {
        if self.str_locator.is_none() {
            let mut loc = StringLocator::new(self.dex);
            loc.set_debug(self.debug);
            self.str_locator = Some(loc);
        }
        let loc = self.str_locator.as_mut().unwrap();
        if build && !loc.parsed {
            loc.build_map();
        }
        loc
    }

    pub fn get_type_locator(&mut self, build: bool) -> &mut TypeLocator<'a> {
        if self.type_locator.is_none() {
            let mut loc = TypeLocator::new(self.dex);
            loc.set_debug(self.debug);
            self.type_locator = Some(loc);
        }
        let loc = self.type_locator.as_mut().unwrap();
        if build && !loc.parsed {
            loc.build_map();
        }
        loc
    }

    pub fn get_method_locator(&mut self, build: bool) -> &mut MethodLocator<'a> {
        if self.method_locator.is_none() {
            let mut loc = MethodLocator::new(self.dex);
            loc.set_debug(self.debug);
            self.method_locator = Some(loc);
        }
        let loc = self.method_locator.as_mut().unwrap();
        if build && !loc.parsed {
            loc.build_map();
        }
        loc
    }

    pub fn get_field_locator(&mut self, build: bool) -> &mut FieldLocator<'a> {
        if self.field_locator.is_none() {
            let mut loc = FieldLocator::new(self.dex);
            loc.set_debug(self.debug);
            self.field_locator = Some(loc);
        }
        let loc = self.field_locator.as_mut().unwrap();
        if build && !loc.parsed {
            loc.build_map();
        }
        loc
    }

    pub fn get_insn_locator(&mut self) -> &mut InsnLocator<'a> {
        if self.insn_locator.is_none() {
            let mut loc = InsnLocator::new(self.dex);
            loc.set_debug(self.debug);
            self.insn_locator = Some(loc);
        }
        let loc = self.insn_locator.as_mut().unwrap();
        if !loc.parsed {
            loc.parse();
        }
        loc
    }

    pub fn find_ref(
        &mut self,
        find: FindQuery,
        mark: bool,
    ) -> (HashMap<String, Vec<Option<MethodIdxEntry>>>, Vec<u32>) {
        let mut target_map: HashMap<String, HashSet<u32>> = HashMap::new();
        let mut has_idx = false;

        // 1. Locate string
        if let Some(s) = find.string {
            let loc = self.get_str_locator(true);
            let idxs = loc.locate(s);
            if !idxs.is_empty() {
                has_idx = true;
            }
            target_map.insert("string".to_string(), idxs);
        }

        // 2. Locate type
        if let Some(t) = find.r#type {
            // Need str_locator for type_locator
            self.get_str_locator(true);
            self.get_type_locator(true);
            let str_loc = self.str_locator.as_mut().unwrap();
            let type_loc = self.type_locator.as_mut().unwrap();
            let idxs = type_loc.locate(t, str_loc);
            if !idxs.is_empty() {
                has_idx = true;
            }
            target_map.insert("type".to_string(), idxs);
        }

        // 3. Locate method
        if let Some(m) = find.method {
            self.get_str_locator(true);
            self.get_type_locator(true);
            self.get_method_locator(true);
            let str_loc = self.str_locator.as_mut().unwrap();
            let type_loc = self.type_locator.as_mut().unwrap();
            let meth_loc = self.method_locator.as_mut().unwrap();
            let idxs = meth_loc.locate(m.class, m.method, str_loc, type_loc);
            if !idxs.is_empty() {
                has_idx = true;
            }
            target_map.insert("method".to_string(), idxs);
        }

        // 4. Locate field
        if let Some(f) = find.field {
            self.get_str_locator(true);
            self.get_type_locator(true);
            self.get_field_locator(true);
            let str_loc = self.str_locator.as_mut().unwrap();
            let type_loc = self.type_locator.as_mut().unwrap();
            let field_loc = self.field_locator.as_mut().unwrap();
            let idxs = field_loc.locate(f.class, f.field, str_loc, type_loc);
            if !idxs.is_empty() {
                has_idx = true;
            }
            target_map.insert("field".to_string(), idxs);
        }

        if target_map.is_empty() || !has_idx {
            let mut empty_results = HashMap::new();
            for k in target_map.keys() {
                empty_results.insert(k.clone(), Vec::new());
            }
            return (empty_results, Vec::new());
        }

        // 5. Scan code items
        self.get_insn_locator();
        let insn_loc = self.insn_locator.as_ref().unwrap();
        let mut scanner = CodeItemScanner::new(insn_loc);
        let results = scanner.scan(&target_map, mark);
        self.last_mark_idx = scanner.mark_idx.clone();

        (results, scanner.mark_idx)
    }
}
