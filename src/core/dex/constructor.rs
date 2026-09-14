//! DEX hollowing structures and logic.
//!
//! Ported from `src/asc_core/core/dex/dex_constructor.py` and `dex_parser.py`.

use std::collections::{HashMap, HashSet};
use crate::core::leb128::{read_uleb128_fast, read_sleb128_fast, read_uleb128_len};
use crate::core::tinydex::Dex;

#[inline(always)]
fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    if off + 2 <= buf.len() {
        u16::from_le_bytes([buf[off], buf[off + 1]])
    } else {
        0
    }
}

#[inline(always)]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    if off + 4 <= buf.len() {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    } else {
        0
    }
}

/// Encoded value representation parsed from DEX.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedValue {
    Index { value_type: u8, idx: u32 },
    Array(Vec<EncodedValue>),
    Annotation {
        type_idx: u32,
        elements: Vec<(u32, EncodedValue)>,
    },
    Immediate { value_type: u8, arg: u8 },
    Raw { value_type: u8, data: Vec<u8> },
}

/// Parsed annotation item.
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
    pub size: usize,
}

/// Parsed encoded annotation.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodedAnnotation {
    pub type_idx: u32,
    pub elements: Vec<(u32, EncodedValue)>,
}

/// Parsed annotation directory item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AnnotationDirectory {
    pub class_annotations_off: u32,
    pub field_annotations: Vec<(u32, u32)>,
    pub method_annotations: Vec<(u32, u32)>,
    pub parameter_annotations: Vec<(u32, u32)>,
}

/// Parsed annotation set item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AnnotationSet {
    pub items: Vec<u32>,
}

/// Parsed debug info item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DebugInfoItem {
    pub line_start: u32,
    pub parameter_names: Vec<u32>,
    pub opcodes: Vec<DebugOpcode>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DebugOpcode {
    EndSequence,
    AdvancePc(u32),
    AdvanceLine(i32),
    StartLocal { v_reg: u32, name_idx: u32, type_idx: u32 },
    StartLocalExtended { v_reg: u32, name_idx: u32, type_idx: u32, sig_idx: u32 },
    EndLocal(u32),
    RestartLocal(u32),
    SetFile(u32),
    Special(u8),
}

/// Catch handler inside code item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EncodedCatchHandler {
    pub old_off: u32,
    pub size: i32,
    pub type_addr_pairs: Vec<(u32, u32)>,
    pub catch_all_addr: Option<u32>,
}

/// Encoded catch handler list for a code item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EncodedCatchHandlerList {
    pub count: u32,
    pub handlers: Vec<EncodedCatchHandler>,
}

// ---------------- Parser routines ----------------

pub fn parse_encoded_value(
    data: &[u8],
    pos: &mut usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> EncodedValue {
    if *pos >= data.len() {
        return EncodedValue::Immediate { value_type: 0x1E, arg: 0 };
    }
    let header = data[*pos];
    *pos += 1;
    let value_type = header & 0x1f;
    let value_arg = (header >> 5) as usize;

    match value_type {
        0x17 | 0x18 | 0x19 | 0x1A | 0x1B => {
            let size = value_arg + 1;
            let mut idx = 0u32;
            for i in 0..size {
                if *pos + i < data.len() {
                    idx |= (data[*pos + i] as u32) << (i * 8);
                }
            }
            *pos += size;

            match value_type {
                0x17 => { hlw_strs.insert(idx); }
                0x18 => { hlw_types.insert(idx); }
                0x19 | 0x1B => { hlw_fields.insert(idx); }
                0x1A => { hlw_methods.insert(idx); }
                _ => {}
            }

            EncodedValue::Index { value_type, idx }
        }
        0x1C => {
            let size = read_uleb128_fast(data, pos) as usize;
            let mut elements = Vec::with_capacity(size);
            for _ in 0..size {
                elements.push(parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods));
            }
            EncodedValue::Array(elements)
        }
        0x1D => {
            let type_idx = read_uleb128_fast(data, pos);
            hlw_types.insert(type_idx);
            let size = read_uleb128_fast(data, pos) as usize;
            let mut elements = Vec::with_capacity(size);
            for _ in 0..size {
                let name_idx = read_uleb128_fast(data, pos);
                hlw_strs.insert(name_idx);
                let elem = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods);
                elements.push((name_idx, elem));
            }
            EncodedValue::Annotation { type_idx, elements }
        }
        0x1E | 0x1F => EncodedValue::Immediate { value_type, arg: value_arg as u8 },
        _ => {
            let size = value_arg + 1;
            let end = (*pos + size).min(data.len());
            let val = data[*pos..end].to_vec();
            *pos += size;
            EncodedValue::Raw { value_type, data: val }
        }
    }
}

pub fn parse_encoded_array(
    data: &[u8],
    mut pos: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> Vec<EncodedValue> {
    let size = read_uleb128_fast(data, &mut pos) as usize;
    let mut elements = Vec::with_capacity(size);
    for _ in 0..size {
        elements.push(parse_encoded_value(data, &mut pos, hlw_strs, hlw_types, hlw_fields, hlw_methods));
    }
    elements
}

pub fn parse_encoded_annotation(
    data: &[u8],
    pos: &mut usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> EncodedAnnotation {
    let type_idx = read_uleb128_fast(data, pos);
    hlw_types.insert(type_idx);
    let size = read_uleb128_fast(data, pos) as usize;
    let mut elements = Vec::with_capacity(size);
    for _ in 0..size {
        let name_idx = read_uleb128_fast(data, pos);
        hlw_strs.insert(name_idx);
        let elem = parse_encoded_value(data, pos, hlw_strs, hlw_types, hlw_fields, hlw_methods);
        elements.push((name_idx, elem));
    }
    EncodedAnnotation { type_idx, elements }
}

pub fn parse_annotation_item(
    data: &[u8],
    off: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
    hlw_fields: &mut HashSet<u32>,
    hlw_methods: &mut HashSet<u32>,
) -> AnnotationItem {
    let visibility = if off < data.len() { data[off] } else { 0 };
    let mut pos = off + 1;
    let annotation = parse_encoded_annotation(data, &mut pos, hlw_strs, hlw_types, hlw_fields, hlw_methods);
    let size = pos - off;
    AnnotationItem {
        visibility,
        annotation,
        size,
    }
}

pub fn parse_debug_info(
    data: &[u8],
    mut pos: usize,
    hlw_strs: &mut HashSet<u32>,
    hlw_types: &mut HashSet<u32>,
) -> DebugInfoItem {
    let line_start = read_uleb128_fast(data, &mut pos);
    let parameters_size = read_uleb128_fast(data, &mut pos) as usize;

    let mut parameter_names = Vec::with_capacity(parameters_size);
    for _ in 0..parameters_size {
        let name_idx = read_uleb128_fast(data, &mut pos);
        parameter_names.push(name_idx);
        if name_idx != 0 {
            hlw_strs.insert(name_idx - 1);
        }
    }

    let mut opcodes = Vec::new();
    while pos < data.len() {
        let opcode = data[pos];
        pos += 1;
        match opcode {
            0x00 => {
                opcodes.push(DebugOpcode::EndSequence);
                break;
            }
            0x01 => {
                let addr_diff = read_uleb128_fast(data, &mut pos);
                opcodes.push(DebugOpcode::AdvancePc(addr_diff));
            }
            0x02 => {
                let line_diff = read_sleb128_fast(data, &mut pos);
                opcodes.push(DebugOpcode::AdvanceLine(line_diff));
            }
            0x03 => {
                let v_reg = read_uleb128_fast(data, &mut pos);
                let name_idx = read_uleb128_fast(data, &mut pos);
                let type_idx = read_uleb128_fast(data, &mut pos);
                if name_idx != 0 { hlw_strs.insert(name_idx - 1); }
                if type_idx != 0 { hlw_types.insert(type_idx - 1); }
                opcodes.push(DebugOpcode::StartLocal { v_reg, name_idx, type_idx });
            }
            0x04 => {
                let v_reg = read_uleb128_fast(data, &mut pos);
                let name_idx = read_uleb128_fast(data, &mut pos);
                let type_idx = read_uleb128_fast(data, &mut pos);
                let sig_idx = read_uleb128_fast(data, &mut pos);
                if name_idx != 0 { hlw_strs.insert(name_idx - 1); }
                if type_idx != 0 { hlw_types.insert(type_idx - 1); }
                if sig_idx != 0 { hlw_strs.insert(sig_idx - 1); }
                opcodes.push(DebugOpcode::StartLocalExtended { v_reg, name_idx, type_idx, sig_idx });
            }
            0x05 => {
                let v_reg = read_uleb128_fast(data, &mut pos);
                opcodes.push(DebugOpcode::EndLocal(v_reg));
            }
            0x06 => {
                let v_reg = read_uleb128_fast(data, &mut pos);
                opcodes.push(DebugOpcode::RestartLocal(v_reg));
            }
            0x09 => {
                let name_idx = read_uleb128_fast(data, &mut pos);
                if name_idx != 0 { hlw_strs.insert(name_idx - 1); }
                opcodes.push(DebugOpcode::SetFile(name_idx));
            }
            special => {
                opcodes.push(DebugOpcode::Special(special));
            }
        }
    }

    DebugInfoItem {
        line_start,
        parameter_names,
        opcodes,
    }
}

// ---------------- DexHollower ----------------

pub struct DexHollower<'a> {
    pub dex: Dex<'a>,
    pub dex_buffer: &'a [u8],
    pub clz_idx: u32,

    // Hollow lists
    pub clz_def_hlw_types: HashMap<u32, u32>,
    pub clz_def_hlw_strs: HashMap<u32, u32>,
    pub ifs_list_hlw_types: Vec<u32>,
    pub anno_dir_hlw_types: HashMap<u32, u32>,

    // Code items
    // method_idx -> (code_item_header_bytes, try_item_bytes, tries_size)
    pub code_item_hlws: HashMap<u32, (Vec<u8>, Option<Vec<u8>>, u16)>,
    // method_idx -> (debug_info_off, Option<EncodedCatchHandlerList>)
    pub code_item_metadata_hlws: HashMap<u32, (u32, Option<EncodedCatchHandlerList>)>,

    pub static_values_elements: Option<Vec<EncodedValue>>,
    pub debug_info_items: HashMap<u32, DebugInfoItem>,
    pub annotation_directory: Option<AnnotationDirectory>,
    pub annotation_sets: HashMap<u32, AnnotationSet>,
    pub annotation_items: HashMap<u32, AnnotationItem>,
    pub annotation_set_refs: HashMap<u32, Vec<u32>>,

    pub hlw_strs: HashSet<u32>,
    pub hlw_types: HashSet<u32>,
    pub hlw_fields: HashSet<u32>,
    pub hlw_methods: HashSet<u32>,

    pub clz_def_offset: usize,
    pub clz_raw_byte: [u8; 32],
}

impl<'a> DexHollower<'a> {
    pub fn new(dex: Dex<'a>, dex_buffer: &'a [u8], clz_str: &str) -> Option<Self> {
        let clz = dex.get_class(clz_str)?;
        let clz_idx = clz.index;
        let clz_def_offset = (dex.header.classes.0 as usize) + (clz_idx as usize) * 32;

        let mut clz_raw_byte = [0u8; 32];
        if clz_def_offset + 32 <= dex_buffer.len() {
            clz_raw_byte.copy_from_slice(&dex_buffer[clz_def_offset..clz_def_offset + 32]);
        }

        Some(Self {
            dex,
            dex_buffer,
            clz_idx,
            clz_def_hlw_types: HashMap::new(),
            clz_def_hlw_strs: HashMap::new(),
            ifs_list_hlw_types: Vec::new(),
            anno_dir_hlw_types: HashMap::new(),
            code_item_hlws: HashMap::new(),
            code_item_metadata_hlws: HashMap::new(),
            static_values_elements: None,
            debug_info_items: HashMap::new(),
            annotation_directory: None,
            annotation_sets: HashMap::new(),
            annotation_items: HashMap::new(),
            annotation_set_refs: HashMap::new(),
            hlw_strs: HashSet::new(),
            hlw_types: HashSet::new(),
            hlw_fields: HashSet::new(),
            hlw_methods: HashSet::new(),
            clz_def_offset,
            clz_raw_byte,
        })
    }

    fn hollow_interface_bytes(&mut self, ifs_off: u32) -> u32 {
        if ifs_off == 0 {
            return 0;
        }
        let off = ifs_off as usize;
        let ifs_size = read_u32_le(self.dex_buffer, off);
        self.ifs_list_hlw_types.push(ifs_size);

        for i in 0..ifs_size {
            let type_idx = read_u16_le(self.dex_buffer, off + 4 + (i as usize) * 2) as u32;
            self.ifs_list_hlw_types.push(type_idx);
        }
        ifs_size
    }

    fn hollow_encoded_catch_handler_list(&self, data: &[u8], mut off: usize) -> EncodedCatchHandlerList {
        let base_off = off;
        let size = read_uleb128_fast(data, &mut off);
        let mut handlers = Vec::with_capacity(size as usize);

        for _ in 0..size {
            let old_off = (off - base_off) as u32;
            let h_size = read_sleb128_fast(data, &mut off);
            let count = h_size.unsigned_abs() as usize;
            let mut pairs = Vec::with_capacity(count);

            for _ in 0..count {
                let type_idx = read_uleb128_fast(data, &mut off);
                let addr = read_uleb128_fast(data, &mut off);
                pairs.push((type_idx, addr));
            }

            let catch_all_addr = if h_size <= 0 {
                Some(read_uleb128_fast(data, &mut off))
            } else {
                None
            };

            handlers.push(EncodedCatchHandler {
                old_off,
                size: h_size,
                type_addr_pairs: pairs,
                catch_all_addr,
            });
        }

        EncodedCatchHandlerList { count: size, handlers }
    }

    fn hollow_class_data_item_bytes(&mut self, off: usize) {
        if off == 0 || off >= self.dex_buffer.len() {
            return;
        }
        let data = self.dex_buffer;
        let mut p = off;

        let s_f_cnt = read_uleb128_fast(data, &mut p);
        let i_f_cnt = read_uleb128_fast(data, &mut p);
        let d_m_cnt = read_uleb128_fast(data, &mut p);
        let v_m_cnt = read_uleb128_fast(data, &mut p);

        // Skip fields
        for _ in 0..(s_f_cnt + i_f_cnt) {
            p += read_uleb128_len(data, p);
            p += read_uleb128_len(data, p);
        }

        // Direct methods
        let mut last_idx = 0u32;
        for _ in 0..d_m_cnt {
            let diff = read_uleb128_fast(data, &mut p);
            last_idx += diff;
            p += read_uleb128_len(data, p); // skip acc

            let val = read_uleb128_fast(data, &mut p);
            if val > 0 {
                let aligned_val = ((val + 3) & !3) as usize;
                if aligned_val + 16 <= data.len() {
                    let code_item_head = data[aligned_val..aligned_val + 16].to_vec();
                    let debug_val = read_u32_le(&code_item_head, 8);
                    let tries_size = read_u16_le(&code_item_head, 6);

                    let (try_item_bytes, encoded_catch_handler_list) = if tries_size != 0 {
                        let insns_size = read_u16_le(&code_item_head, 12) as usize;
                        let insns_end = aligned_val + 16 + insns_size * 2;
                        let try_off = (insns_end + 3) & !3;
                        let try_off_end = try_off + (tries_size as usize) * 8;
                        let t_bytes = if try_off_end <= data.len() {
                            Some(data[try_off..try_off_end].to_vec())
                        } else {
                            None
                        };
                        let handlers = self.hollow_encoded_catch_handler_list(data, try_off_end);
                        (t_bytes, Some(handlers))
                    } else {
                        (None, None)
                    };

                    self.code_item_hlws.insert(last_idx, (code_item_head, try_item_bytes, tries_size));
                    self.code_item_metadata_hlws.insert(last_idx, (debug_val, encoded_catch_handler_list));
                }
            }
        }

        // Virtual methods
        last_idx = 0;
        for _ in 0..v_m_cnt {
            let diff = read_uleb128_fast(data, &mut p);
            last_idx += diff;
            p += read_uleb128_len(data, p); // skip acc

            let val = read_uleb128_fast(data, &mut p);
            if val > 0 {
                let aligned_val = ((val + 3) & !3) as usize;
                if aligned_val + 16 <= data.len() {
                    let code_item_head = data[aligned_val..aligned_val + 16].to_vec();
                    let debug_val = read_u32_le(&code_item_head, 8);
                    let tries_size = read_u16_le(&code_item_head, 6);

                    let (try_item_bytes, encoded_catch_handler_list) = if tries_size != 0 {
                        let insns_size = read_u16_le(&code_item_head, 12) as usize;
                        let insns_end = aligned_val + 16 + insns_size * 2;
                        let try_off = (insns_end + 3) & !3;
                        let try_off_end = try_off + (tries_size as usize) * 8;
                        let t_bytes = if try_off_end <= data.len() {
                            Some(data[try_off..try_off_end].to_vec())
                        } else {
                            None
                        };
                        let handlers = self.hollow_encoded_catch_handler_list(data, try_off_end);
                        (t_bytes, Some(handlers))
                    } else {
                        (None, None)
                    };

                    self.code_item_hlws.insert(last_idx, (code_item_head, try_item_bytes, tries_size));
                    self.code_item_metadata_hlws.insert(last_idx, (debug_val, encoded_catch_handler_list));
                }
            }
        }
    }

    fn hollow_annotation_set_item(&mut self, off: usize) {
        if off == 0 || self.annotation_sets.contains_key(&(off as u32)) || off + 4 > self.dex_buffer.len() {
            return;
        }
        let data = self.dex_buffer;
        let size = read_u32_le(data, off) as usize;
        let mut items = Vec::with_capacity(size);
        let mut p = off + 4;

        for _ in 0..size {
            if p + 4 > data.len() { break; }
            let annotation_off = read_u32_le(data, p);
            p += 4;
            items.push(annotation_off);
            if annotation_off != 0 && !self.annotation_items.contains_key(&annotation_off) {
                let parsed = parse_annotation_item(
                    data,
                    annotation_off as usize,
                    &mut self.hlw_strs,
                    &mut self.hlw_types,
                    &mut self.hlw_fields,
                    &mut self.hlw_methods,
                );
                self.annotation_items.insert(annotation_off, parsed);
            }
        }

        self.annotation_sets.insert(off as u32, AnnotationSet { items });
    }

    fn hollow_annotation_set_ref_list(&mut self, off: usize) {
        if off == 0 || self.annotation_set_refs.contains_key(&(off as u32)) || off + 4 > self.dex_buffer.len() {
            return;
        }
        let data = self.dex_buffer;
        let size = read_u32_le(data, off) as usize;
        let mut refs = Vec::with_capacity(size);
        let mut p = off + 4;

        for _ in 0..size {
            if p + 4 > data.len() { break; }
            let set_off = read_u32_le(data, p);
            p += 4;
            refs.push(set_off);
            self.hollow_annotation_set_item(set_off as usize);
        }

        self.annotation_set_refs.insert(off as u32, refs);
    }

    fn hollow_annotation_directory_item(&mut self, off: usize) {
        if off == 0 || off + 16 > self.dex_buffer.len() {
            return;
        }
        let data = self.dex_buffer;
        let class_annotations_off = read_u32_le(data, off);
        let fields_size = read_u32_le(data, off + 4) as usize;
        let methods_size = read_u32_le(data, off + 8) as usize;
        let parameters_size = read_u32_le(data, off + 12) as usize;

        self.hollow_annotation_set_item(class_annotations_off as usize);

        let mut p = off + 16;
        let mut field_annotations = Vec::with_capacity(fields_size);
        for _ in 0..fields_size {
            if p + 8 > data.len() { break; }
            let field_idx = read_u32_le(data, p);
            let annotations_off = read_u32_le(data, p + 4);
            p += 8;
            field_annotations.push((field_idx, annotations_off));
            self.hlw_fields.insert(field_idx);
            self.hollow_annotation_set_item(annotations_off as usize);
        }

        let mut method_annotations = Vec::with_capacity(methods_size);
        for _ in 0..methods_size {
            if p + 8 > data.len() { break; }
            let method_idx = read_u32_le(data, p);
            let annotations_off = read_u32_le(data, p + 4);
            p += 8;
            method_annotations.push((method_idx, annotations_off));
            self.hlw_methods.insert(method_idx);
            self.hollow_annotation_set_item(annotations_off as usize);
        }

        let mut parameter_annotations = Vec::with_capacity(parameters_size);
        for _ in 0..parameters_size {
            if p + 8 > data.len() { break; }
            let method_idx = read_u32_le(data, p);
            let annotations_off = read_u32_le(data, p + 4);
            p += 8;
            parameter_annotations.push((method_idx, annotations_off));
            self.hlw_methods.insert(method_idx);
            self.hollow_annotation_set_ref_list(annotations_off as usize);
        }

        self.annotation_directory = Some(AnnotationDirectory {
            class_annotations_off,
            field_annotations,
            method_annotations,
            parameter_annotations,
        });
    }

    /// Primary entry point: extracts and hollows class definition and referenced items.
    pub fn hollow(&mut self) {
        let class_idx = read_u32_le(&self.clz_raw_byte, 0);
        let superclass_idx = read_u32_le(&self.clz_raw_byte, 8);
        let interfaces_off = read_u32_le(&self.clz_raw_byte, 12);
        let source_file_idx = read_u32_le(&self.clz_raw_byte, 16);
        let annotations_off = read_u32_le(&self.clz_raw_byte, 20);
        let class_data_off = read_u32_le(&self.clz_raw_byte, 24);
        let static_values_off = read_u32_le(&self.clz_raw_byte, 28);

        self.clz_def_hlw_types.insert(0, class_idx);
        self.clz_def_hlw_types.insert(8, superclass_idx);
        self.clz_def_hlw_strs.insert(16, source_file_idx);

        self.hollow_interface_bytes(interfaces_off);
        self.hollow_annotation_directory_item(annotations_off as usize);
        self.hollow_class_data_item_bytes(class_data_off as usize);

        if static_values_off != 0 {
            self.static_values_elements = Some(parse_encoded_array(
                self.dex_buffer,
                static_values_off as usize,
                &mut self.hlw_strs,
                &mut self.hlw_types,
                &mut self.hlw_fields,
                &mut self.hlw_methods,
            ));
        }

        let code_keys: Vec<u32> = self.code_item_hlws.keys().copied().collect();
        for method_idx in code_keys {
            if let Some(&(debug_info_off, _)) = self.code_item_metadata_hlws.get(&method_idx) {
                if debug_info_off != 0 {
                    let parsed = parse_debug_info(
                        self.dex_buffer,
                        debug_info_off as usize,
                        &mut self.hlw_strs,
                        &mut self.hlw_types,
                    );
                    self.debug_info_items.insert(method_idx, parsed);
                }
            }
        }
    }
}
