//! Locators for strings, types, fields, methods, and instructions in DEX.

use std::collections::{HashMap, HashSet};
use crate::core::tinydex::Dex;
use crate::core::leb128::{read_uleb128_fast, read_uleb128_len};
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
// StringLocator
// ---------------------------------------------------------------------------

pub struct StringLocator<'a> {
    dex: Dex<'a>,
    pub stridx_map: HashMap<u32, u32>,
    pub strdata_start: u32,
    pub strdata_end: u32,
    pub parsed: bool,
    debug: bool,
}

impl<'a> StringLocator<'a> {
    pub fn new(dex: Dex<'a>) -> Self {
        Self {
            dex,
            stridx_map: HashMap::new(),
            strdata_start: 0,
            strdata_end: 0,
            parsed: false,
            debug: false,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn build_map(&mut self) {
        if self.parsed {
            return;
        }
        let (string_ids_off, string_ids_size) = self.dex.header.strings;
        let buf = self.dex.buf;

        if string_ids_size == 0 {
            self.parsed = true;
            return;
        }

        let mut off = string_ids_off as usize;
        self.strdata_start = read_u32(buf, off);

        self.stridx_map.reserve(string_ids_size as usize + 1);
        let mut last_data_offset = 0u32;
        for idx in 0..string_ids_size {
            let data_offset = read_u32(buf, off);
            off += 4;
            self.stridx_map.insert(data_offset, idx);
            last_data_offset = data_offset;
        }

        // Include the final string_data_item sentinel.
        let uleb_len = read_uleb128_len(buf, last_data_offset as usize);
        let search_start = last_data_offset as usize + uleb_len;
        if search_start < buf.len() {
            if let Some(pos) = buf[search_start..].iter().position(|&b| b == 0) {
                self.strdata_end = (search_start + pos + 1) as u32;
            } else {
                self.strdata_end = buf.len() as u32;
            }
        } else {
            self.strdata_end = buf.len() as u32;
        }

        self.stridx_map.insert(self.strdata_end, string_ids_size);
        self.parsed = true;
    }

    pub fn match_string_offset(&self, query: &str) -> Vec<u32> {
        let buf = self.dex.buf;
        let query_bytes = query.as_bytes();
        let strdata_start = self.strdata_start as usize;
        let strdata_end = (self.strdata_end as usize).min(buf.len());

        if strdata_start >= strdata_end {
            return Vec::new();
        }

        let submem = &buf[strdata_start..strdata_end];
        let escaped = regex::escape(query);
        let pattern = match Regex::new(&escaped) {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };

        let mut offsets = Vec::new();
        for m in pattern.find_iter(submem) {
            let offset_in_buf = strdata_start + m.end();
            if offset_in_buf < strdata_end {
                if let Some(null_pos) = buf[offset_in_buf..strdata_end].iter().position(|&b| b == 0) {
                    offsets.push((offset_in_buf + null_pos + 1) as u32);
                }
            }
        }
        offsets
    }

    pub fn locate(&mut self, query: &str) -> HashSet<u32> {
        if !self.parsed {
            self.build_map();
        }
        let mut located_idx = HashSet::new();
        let offsets = self.match_string_offset(query);
        for offset in offsets {
            if let Some(&idx) = self.stridx_map.get(&offset) {
                if idx > 0 {
                    located_idx.insert(idx - 1);
                }
            }
        }
        located_idx
    }
}

// ---------------------------------------------------------------------------
// TypeLocator
// ---------------------------------------------------------------------------

pub struct TypeLocator<'a> {
    dex: Dex<'a>,
    pub type_maps: HashMap<u32, HashSet<u32>>, // str_idx -> {type_idx}
    pub parsed: bool,
    debug: bool,
}

impl<'a> TypeLocator<'a> {
    pub fn new(dex: Dex<'a>) -> Self {
        Self {
            dex,
            type_maps: HashMap::new(),
            parsed: false,
            debug: false,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn build_map(&mut self) {
        if self.parsed {
            return;
        }
        let (type_ids_off, type_ids_size) = self.dex.header.types;
        let buf = self.dex.buf;

        let mut off = type_ids_off as usize;
        for type_idx in 0..type_ids_size {
            let str_idx = read_u32(buf, off);
            off += 4;
            self.type_maps.entry(str_idx).or_default().insert(type_idx);
        }
        self.parsed = true;
    }

    pub fn locate(&mut self, type_str: &str, str_locator: &mut StringLocator<'a>) -> HashSet<u32> {
        if !self.parsed {
            self.build_map();
        }
        if type_str.is_empty() {
            return HashSet::new();
        }

        let str_idxs = str_locator.locate(type_str);
        let mut ret = HashSet::new();
        for str_idx in str_idxs {
            if let Some(types) = self.type_maps.get(&str_idx) {
                ret.extend(types);
            }
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// MethodLocator
// ---------------------------------------------------------------------------

pub struct MethodLocator<'a> {
    dex: Dex<'a>,
    pub clz_maps: HashMap<u16, HashSet<u32>>,   // type_idx -> {method_idx}
    pub method_maps: HashMap<u32, HashSet<u32>>, // name_idx -> {method_idx}
    pub parsed: bool,
    debug: bool,
}

impl<'a> MethodLocator<'a> {
    pub fn new(dex: Dex<'a>) -> Self {
        Self {
            dex,
            clz_maps: HashMap::new(),
            method_maps: HashMap::new(),
            parsed: false,
            debug: false,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn build_map(&mut self) {
        if self.parsed {
            return;
        }
        let (method_ids_off, method_ids_size) = self.dex.header.methods;
        let buf = self.dex.buf;

        let mut off = method_ids_off as usize;
        for method_idx in 0..method_ids_size {
            let class_idx = read_u16(buf, off);
            let name_idx = read_u32(buf, off + 4);
            off += 8;
            self.clz_maps.entry(class_idx).or_default().insert(method_idx);
            self.method_maps.entry(name_idx).or_default().insert(method_idx);
        }
        self.parsed = true;
    }

    pub fn find_type_idx_precisely(&self, clz: &str) -> i32 {
        let (type_ids_off, type_ids_size) = self.dex.header.types;
        if type_ids_size == 0 {
            return -1;
        }
        let buf = self.dex.buf;
        let mut left = 0i32;
        let mut right = (type_ids_size - 1) as i32;

        while left <= right {
            let mid = (left + right) >> 1;
            let offset = type_ids_off as usize + (mid as usize * 4);
            let desc_idx = read_u32(buf, offset);
            let desc = match self.dex.get_string(desc_idx) {
                Some(d) => d,
                None => return -1,
            };

            let cmp = desc.as_ref().cmp(clz);
            if cmp == std::cmp::Ordering::Equal {
                return mid;
            } else if cmp == std::cmp::Ordering::Less {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }
        -1
    }

    fn collect_clz_mids(&self, type_idxs: &HashSet<u32>) -> HashSet<u32> {
        let mut ret = HashSet::new();
        for &type_idx in type_idxs {
            if let Some(mids) = self.clz_maps.get(&(type_idx as u16)) {
                ret.extend(mids);
            }
        }
        ret
    }

    fn match_clz_mids(&self, clz_mids: &HashSet<u32>, method: &str) -> HashSet<u32> {
        let mut ret = HashSet::new();
        for &mid in clz_mids {
            if let Some(m) = self.dex.get_method(mid) {
                if let Some(name) = m.name(&self.dex) {
                    if name.contains(method) {
                        ret.insert(mid);
                    }
                }
            }
        }
        ret
    }

    pub fn locate(
        &mut self,
        clz_query: Option<(&str, bool)>, // (clz_name, is_precise)
        method_name: Option<&str>,
        str_locator: &mut StringLocator<'a>,
        type_locator: &mut TypeLocator<'a>,
    ) -> HashSet<u32> {
        if !self.parsed {
            self.build_map();
        }

        let clz_info = clz_query.and_then(|(c, p)| {
            let trimmed = c.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some((trimmed, p))
            }
        });

        let method = method_name.and_then(|m| {
            let trimmed = m.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        if clz_info.is_none() && method.is_none() {
            return HashSet::new();
        }

        if clz_info.is_none() {
            let m_name = method.unwrap();
            let name_idxs = str_locator.locate(m_name);
            let mut ret = HashSet::new();
            for name_idx in name_idxs {
                if let Some(mids) = self.method_maps.get(&name_idx) {
                    ret.extend(mids);
                }
            }
            return ret;
        }

        let (clz, clz_precise) = clz_info.unwrap();
        let clz_mids: HashSet<u32> = if clz_precise {
            let type_idx = self.find_type_idx_precisely(clz);
            if type_idx == -1 {
                return HashSet::new();
            }
            match self.clz_maps.get(&(type_idx as u16)) {
                Some(mids) => mids.clone(),
                None => return HashSet::new(),
            }
        } else {
            let type_idxs = type_locator.locate(clz, str_locator);
            let mids = self.collect_clz_mids(&type_idxs);
            if mids.is_empty() {
                return HashSet::new();
            }
            mids
        };

        if method.is_none() {
            return clz_mids;
        }

        let m_name = method.unwrap();
        if clz_precise {
            return self.match_clz_mids(&clz_mids, m_name);
        }

        let name_idxs = str_locator.locate(m_name);
        let mut ret = HashSet::new();
        for name_idx in name_idxs {
            if let Some(mids) = self.method_maps.get(&name_idx) {
                for &mid in mids {
                    if clz_mids.contains(&mid) {
                        ret.insert(mid);
                    }
                }
            }
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// FieldLocator
// ---------------------------------------------------------------------------

pub struct FieldLocator<'a> {
    dex: Dex<'a>,
    pub clz_maps: HashMap<u16, HashSet<u32>>,   // type_idx -> {field_idx}
    pub field_maps: HashMap<u32, HashSet<u32>>, // name_idx -> {field_idx}
    pub parsed: bool,
    debug: bool,
}

impl<'a> FieldLocator<'a> {
    pub fn new(dex: Dex<'a>) -> Self {
        Self {
            dex,
            clz_maps: HashMap::new(),
            field_maps: HashMap::new(),
            parsed: false,
            debug: false,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    pub fn build_map(&mut self) {
        if self.parsed {
            return;
        }
        let (field_ids_off, field_ids_size) = self.dex.header.fields;
        let buf = self.dex.buf;

        let mut off = field_ids_off as usize;
        for field_idx in 0..field_ids_size {
            let class_idx = read_u16(buf, off);
            let name_idx = read_u32(buf, off + 4);
            off += 8;
            self.clz_maps.entry(class_idx).or_default().insert(field_idx);
            self.field_maps.entry(name_idx).or_default().insert(field_idx);
        }
        self.parsed = true;
    }

    pub fn find_type_idx_precisely(&self, clz: &str) -> i32 {
        let (type_ids_off, type_ids_size) = self.dex.header.types;
        if type_ids_size == 0 {
            return -1;
        }
        let buf = self.dex.buf;
        let mut left = 0i32;
        let mut right = (type_ids_size - 1) as i32;

        while left <= right {
            let mid = (left + right) >> 1;
            let offset = type_ids_off as usize + (mid as usize * 4);
            let desc_idx = read_u32(buf, offset);
            let desc = match self.dex.get_string(desc_idx) {
                Some(d) => d,
                None => return -1,
            };

            let cmp = desc.as_ref().cmp(clz);
            if cmp == std::cmp::Ordering::Equal {
                return mid;
            } else if cmp == std::cmp::Ordering::Less {
                left = mid + 1;
            } else {
                right = mid - 1;
            }
        }
        -1
    }

    fn collect_clz_fids(&self, type_idxs: &HashSet<u32>) -> HashSet<u32> {
        let mut ret = HashSet::new();
        for &type_idx in type_idxs {
            if let Some(fids) = self.clz_maps.get(&(type_idx as u16)) {
                ret.extend(fids);
            }
        }
        ret
    }

    fn match_clz_fids(&self, clz_fids: &HashSet<u32>, field: &str) -> HashSet<u32> {
        let mut ret = HashSet::new();
        for &fid in clz_fids {
            if let Some(f) = self.dex.get_field(fid) {
                if let Some(name) = f.name(&self.dex) {
                    if name.contains(field) {
                        ret.insert(fid);
                    }
                }
            }
        }
        ret
    }

    pub fn locate(
        &mut self,
        clz_query: Option<(&str, bool)>, // (clz_name, is_precise)
        field_name: Option<&str>,
        str_locator: &mut StringLocator<'a>,
        type_locator: &mut TypeLocator<'a>,
    ) -> HashSet<u32> {
        if !self.parsed {
            self.build_map();
        }

        let clz_info = clz_query.and_then(|(c, p)| {
            let trimmed = c.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some((trimmed, p))
            }
        });

        let field = field_name.and_then(|f| {
            let trimmed = f.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        if clz_info.is_none() && field.is_none() {
            return HashSet::new();
        }

        if clz_info.is_none() {
            let f_name = field.unwrap();
            let name_idxs = str_locator.locate(f_name);
            let mut ret = HashSet::new();
            for name_idx in name_idxs {
                if let Some(fids) = self.field_maps.get(&name_idx) {
                    ret.extend(fids);
                }
            }
            return ret;
        }

        let (clz, clz_precise) = clz_info.unwrap();
        let clz_fids: HashSet<u32> = if clz_precise {
            let type_idx = self.find_type_idx_precisely(clz);
            if type_idx == -1 {
                return HashSet::new();
            }
            match self.clz_maps.get(&(type_idx as u16)) {
                Some(fids) => fids.clone(),
                None => return HashSet::new(),
            }
        } else {
            let type_idxs = type_locator.locate(clz, str_locator);
            let fids = self.collect_clz_fids(&type_idxs);
            if fids.is_empty() {
                return HashSet::new();
            }
            fids
        };

        if field.is_none() {
            return clz_fids;
        }

        let f_name = field.unwrap();
        if clz_precise {
            return self.match_clz_fids(&clz_fids, f_name);
        }

        let name_idxs = str_locator.locate(f_name);
        let mut ret = HashSet::new();
        for name_idx in name_idxs {
            if let Some(fids) = self.field_maps.get(&name_idx) {
                for &fid in fids {
                    if clz_fids.contains(&fid) {
                        ret.insert(fid);
                    }
                }
            }
        }
        ret
    }
}

// ---------------------------------------------------------------------------
// InsnLocator
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodIdxEntry {
    Single(u32),
    Multiple(Vec<u32>),
}

impl MethodIdxEntry {
    pub fn add(&mut self, midx: u32) {
        match self {
            MethodIdxEntry::Single(old) => {
                *self = MethodIdxEntry::Multiple(vec![midx, *old]);
            }
            MethodIdxEntry::Multiple(list) => {
                list.push(midx);
            }
        }
    }

    pub fn first(&self) -> u32 {
        match self {
            MethodIdxEntry::Single(m) => *m,
            MethodIdxEntry::Multiple(v) => v[0],
        }
    }

    pub fn to_vec(&self) -> Vec<u32> {
        match self {
            MethodIdxEntry::Single(m) => vec![*m],
            MethodIdxEntry::Multiple(v) => v.clone(),
        }
    }
}

pub struct InsnLocator<'a> {
    pub dex: Dex<'a>,
    pub parsed: bool,
    pub insn_maps: HashMap<usize, MethodIdxEntry>, // bucket (insn_off >> 4) -> MethodIdxEntry
    pub code_item_start: usize,
    pub code_item_end: usize,
    pub method_bounds: HashMap<u32, usize>, // midx -> insn_off_start
    debug: bool,
}

impl<'a> InsnLocator<'a> {
    pub fn new(dex: Dex<'a>) -> Self {
        Self {
            dex,
            parsed: false,
            insn_maps: HashMap::new(),
            code_item_start: 0,
            code_item_end: 0,
            method_bounds: HashMap::new(),
            debug: false,
        }
    }

    pub fn set_debug(&mut self, debug: bool) {
        self.debug = debug;
    }

    fn encoded_method_parse(&mut self, pos: usize, midx: u32) {
        if pos == 0 {
            return;
        }
        let buf = self.dex.buf;
        if pos + 16 > buf.len() {
            return;
        }
        let insn_size = read_u32(buf, pos + 12) as usize;
        let insn_off = pos + 16;

        let insn_bucket_start = insn_off >> 4;
        let insn_bucket_end = if insn_size > 0 {
            (insn_off + insn_size * 2 - 1) >> 4
        } else {
            insn_bucket_start
        };

        self.method_bounds.insert(midx, insn_off);

        let entry = match self.insn_maps.get_mut(&insn_bucket_start) {
            Some(existing) => {
                existing.add(midx);
                existing.clone()
            }
            None => MethodIdxEntry::Single(midx),
        };

        for b in insn_bucket_start..=insn_bucket_end {
            self.insn_maps.insert(b, entry.clone());
        }
    }

    fn class_data_parse(&mut self, mut pos: usize) -> usize {
        let buf = self.dex.buf;
        let static_fields_size = read_uleb128_fast(buf, &mut pos);
        let instance_fields_size = read_uleb128_fast(buf, &mut pos);
        let direct_methods_size = read_uleb128_fast(buf, &mut pos);
        let virtual_methods_size = read_uleb128_fast(buf, &mut pos);

        for _ in 0..(static_fields_size + instance_fields_size) {
            let l1 = read_uleb128_len(buf, pos);
            pos += l1;
            let l2 = read_uleb128_len(buf, pos);
            pos += l2;
        }

        let mut method_idx = 0u32;
        for _ in 0..direct_methods_size {
            let diff = read_uleb128_fast(buf, &mut pos);
            method_idx += diff;
            let _flags = read_uleb128_fast(buf, &mut pos);
            let code_off = read_uleb128_fast(buf, &mut pos);
            self.encoded_method_parse(code_off as usize, method_idx);
        }

        let mut method_idx = 0u32;
        for _ in 0..virtual_methods_size {
            let diff = read_uleb128_fast(buf, &mut pos);
            method_idx += diff;
            let _flags = read_uleb128_fast(buf, &mut pos);
            let code_off = read_uleb128_fast(buf, &mut pos);
            self.encoded_method_parse(code_off as usize, method_idx);
        }

        pos
    }

    fn build_map_bydef(&mut self) {
        if self.parsed {
            return;
        }
        let (class_def_off, class_def_size) = self.dex.header.classes;
        let buf = self.dex.buf;
        let mut off = class_def_off as usize;

        for _ in 0..class_def_size {
            if off + 28 <= buf.len() {
                let class_data_off = read_u32(buf, off + 24) as usize;
                if class_data_off != 0 {
                    self.class_data_parse(class_data_off);
                }
            }
            off += 32;
        }
    }

    fn build_map_bymap(&mut self) {
        if self.parsed {
            return;
        }
        let mapoff = self.dex.header.mapoff as usize;
        let buf = self.dex.buf;

        if mapoff == 0 || mapoff + 4 > buf.len() {
            self.build_map_bydef();
            return;
        }

        let mapsize = read_u32(buf, mapoff) as usize;
        let mut cur_mapoff = mapoff + 4;
        let mut found_class_data = false;

        for _ in 0..mapsize {
            if cur_mapoff + 12 > buf.len() {
                break;
            }
            let mtype = read_u16(buf, cur_mapoff);
            if mtype == 0x2000 {
                found_class_data = true;
                break;
            }
            cur_mapoff += 12;
        }

        if !found_class_data || cur_mapoff + 12 > buf.len() {
            self.build_map_bydef();
            return;
        }

        let class_data_size = read_u32(buf, cur_mapoff + 4) as usize;
        let mut class_data_off = read_u32(buf, cur_mapoff + 8) as usize;

        for _ in 0..class_data_size {
            class_data_off = self.class_data_parse(class_data_off);
        }
    }

    pub fn parse(&mut self) {
        if self.parsed {
            return;
        }
        self.build_map_bymap();
        if !self.insn_maps.is_empty() {
            let min_bucket = self.insn_maps.keys().copied().min().unwrap_or(0);
            let max_bucket = self.insn_maps.keys().copied().max().unwrap_or(0);
            self.code_item_start = min_bucket << 4;
            self.code_item_end = (max_bucket + 1) << 4;
        }
        self.parsed = true;
    }

    pub fn locate(&self, offsets: &[usize]) -> Vec<Option<MethodIdxEntry>> {
        if !self.parsed {
            return Vec::new();
        }

        let buf = self.dex.buf;
        let mut ret_table = Vec::with_capacity(offsets.len());
        let mut dynamic_bounds: HashMap<u32, usize> = HashMap::new();

        for &off in offsets {
            let bucket = off >> 4;
            match self.insn_maps.get(&bucket) {
                Some(entry) => {
                    let first_midx = entry.first();
                    let start_bound = dynamic_bounds
                        .get(&first_midx)
                        .copied()
                        .or_else(|| self.method_bounds.get(&first_midx).copied())
                        .unwrap_or(0);

                    if verify_insns_range(buf, start_bound, off) {
                        ret_table.push(Some(entry.clone()));
                        dynamic_bounds.insert(first_midx, off);
                    } else {
                        ret_table.push(None);
                    }
                }
                None => {
                    ret_table.push(None);
                }
            }
        }

        ret_table
    }
}

// ---------------------------------------------------------------------------
// Instruction verification
// ---------------------------------------------------------------------------

/// Dalvik opcode lengths in 16-bit code units (1 unit = 2 bytes).
/// An instruction of length N code units takes N * 2 bytes.
/// Returns 0 for invalid/unknown opcode.
#[inline(always)]
pub fn dalvik_opcode_length(opcode: u8) -> usize {
    match opcode {
        // 1 code unit (2 bytes)
        0x00 | 0x01 | 0x04 | 0x07 | 0x0a | 0x0b | 0x0c | 0x0d
        | 0x0e | 0x0f | 0x10 | 0x11 | 0x12 | 0x1d | 0x1e | 0x21
        | 0x27 | 0x28 | 0x7b | 0x7c | 0x7d | 0x7e | 0x7f | 0x80
        | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88
        | 0x89 | 0x8a | 0x8b | 0x8c | 0x8d | 0x8e | 0x8f
        | 0xb0..=0xcf | 0x29 => {
            if opcode == 0x29 {
                2 // goto/16
            } else {
                1
            }
        }
        // 2 code units (4 bytes)
        0x02 | 0x05 | 0x08 | 0x13 | 0x15 | 0x16 | 0x19 | 0x1a
        | 0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x2d..=0x40
        | 0x44..=0x6d | 0x90..=0xaf | 0xd0..=0xe2 | 0xfe | 0xff => 2,
        // 3 code units (6 bytes)
        0x03 | 0x06 | 0x09 | 0x14 | 0x17 | 0x1b | 0x24 | 0x25
        | 0x26 | 0x2a | 0x2b | 0x2c | 0x6e..=0x72 | 0x74..=0x78
        | 0xfc | 0xfd => 3,
        // 4 code units (8 bytes)
        0xfa | 0xfb => 4,
        // 5 code units (10 bytes)
        0x18 => 5,
        _ => 0,
    }
}

/// Verify that the byte range `[start..end]` consists of contiguous valid Dalvik instructions.
#[inline]
pub fn verify_insns_range(buf: &[u8], start: usize, end: usize) -> bool {
    if start == end {
        return true;
    }
    if start > end || end > buf.len() {
        return false;
    }

    let mut pos = start;
    while pos < end {
        let op = buf[pos];
        let units = dalvik_opcode_length(op);
        if units == 0 {
            return false;
        }
        pos += units * 2;
    }

    pos == end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dalvik_opcode_length() {
        assert_eq!(dalvik_opcode_length(0x00), 1); // nop
        assert_eq!(dalvik_opcode_length(0x1a), 2); // const-string
        assert_eq!(dalvik_opcode_length(0x1b), 3); // const-string/jumbo
        assert_eq!(dalvik_opcode_length(0xfa), 4); // invoke-polymorphic
        assert_eq!(dalvik_opcode_length(0x18), 5); // const-wide
    }
}

