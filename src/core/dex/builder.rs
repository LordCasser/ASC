//! DEX binary builder reassembling restructured DEX tables into raw bytes.
//!
//! Ported from `src/asc_core/core/dex/dex_builder.py` and `dex_parser.py` (rebuilders).

use std::collections::HashMap;
use crate::core::leb128::{write_uleb128, write_sleb128};
use crate::core::dex::remapper::DexIndexMapper;
use crate::core::dex::constructor::{
    DexHollower, EncodedValue, EncodedAnnotation, AnnotationItem, DebugInfoItem, DebugOpcode,
};

#[inline(always)]
fn align_to(buf: &mut Vec<u8>, align: usize) {
    while buf.len() % align != 0 {
        buf.push(0);
    }
}

// ---------------- Rebuilder routines ----------------

pub fn rebuild_encoded_value(elem: &EncodedValue, im: &DexIndexMapper<'_>, out: &mut Vec<u8>) {
    match elem {
        EncodedValue::Index { value_type, idx } => {
            let new_idx = match value_type {
                0x17 => {
                    let s = im.dex.get_string(*idx).unwrap_or_default();
                    im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0)
                }
                0x18 => im.type_restruct_idx.get(idx).copied().unwrap_or(0),
                0x19 | 0x1B => im.field_restruct_idx.get(idx).copied().unwrap_or(0),
                0x1A => im.method_restruct_idx.get(idx).copied().unwrap_or(0),
                _ => 0,
            };

            let mut temp = new_idx;
            let mut size = 1usize;
            while temp > 0xff {
                temp >>= 8;
                size += 1;
            }

            out.push((((size - 1) as u8) << 5) | value_type);
            let mut val = new_idx;
            for _ in 0..size {
                out.push((val & 0xff) as u8);
                val >>= 8;
            }
        }
        EncodedValue::Array(elements) => {
            out.push(0x1C);
            out.extend(write_uleb128(elements.len() as u32));
            for e in elements {
                rebuild_encoded_value(e, im, out);
            }
        }
        EncodedValue::Annotation { type_idx, elements } => {
            out.push(0x1D);
            let new_type_idx = im.type_restruct_idx.get(type_idx).copied().unwrap_or(0);
            out.extend(write_uleb128(new_type_idx));
            out.extend(write_uleb128(elements.len() as u32));
            for (name_idx, e) in elements {
                let s = im.dex.get_string(*name_idx).unwrap_or_default();
                let new_name_idx = im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0);
                out.extend(write_uleb128(new_name_idx));
                rebuild_encoded_value(e, im, out);
            }
        }
        EncodedValue::Immediate { value_type, arg } => {
            out.push(((*arg) << 5) | value_type);
        }
        EncodedValue::Raw { value_type, data } => {
            let size = data.len();
            let arg = if size > 0 { (size - 1) as u8 } else { 0 };
            out.push((arg << 5) | value_type);
            out.extend_from_slice(data);
        }
    }
}

pub fn rebuild_encoded_array(elements: &[EncodedValue], im: &DexIndexMapper<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(write_uleb128(elements.len() as u32));
    for e in elements {
        rebuild_encoded_value(e, im, &mut out);
    }
    out
}

pub fn rebuild_encoded_annotation(annotation: &EncodedAnnotation, im: &DexIndexMapper<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    let new_type_idx = im.type_restruct_idx.get(&annotation.type_idx).copied().unwrap_or(0);
    out.extend(write_uleb128(new_type_idx));
    out.extend(write_uleb128(annotation.elements.len() as u32));
    for (name_idx, elem) in &annotation.elements {
        let s = im.dex.get_string(*name_idx).unwrap_or_default();
        let new_name_idx = im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0);
        out.extend(write_uleb128(new_name_idx));
        rebuild_encoded_value(elem, im, &mut out);
    }
    out
}

pub fn rebuild_annotation_item(item: &AnnotationItem, im: &DexIndexMapper<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(item.visibility);
    out.extend(rebuild_encoded_annotation(&item.annotation, im));
    out
}

pub fn rebuild_debug_info(info: &DebugInfoItem, im: &DexIndexMapper<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(write_uleb128(info.line_start));
    out.extend(write_uleb128(info.parameter_names.len() as u32));

    for &name_idx in &info.parameter_names {
        if name_idx == 0 {
            out.extend(write_uleb128(0));
        } else {
            let orig_idx = name_idx - 1;
            let s = im.dex.get_string(orig_idx).unwrap_or_default();
            let new_idx = im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0);
            out.extend(write_uleb128(new_idx + 1));
        }
    }

    for op in &info.opcodes {
        match op {
            DebugOpcode::EndSequence => {
                out.push(0x00);
            }
            DebugOpcode::AdvancePc(addr_diff) => {
                out.push(0x01);
                out.extend(write_uleb128(*addr_diff));
            }
            DebugOpcode::AdvanceLine(line_diff) => {
                out.push(0x02);
                out.extend(write_sleb128(*line_diff));
            }
            DebugOpcode::StartLocal { v_reg, name_idx, type_idx } => {
                out.push(0x03);
                out.extend(write_uleb128(*v_reg));
                let new_name_idx = if *name_idx != 0 {
                    let s = im.dex.get_string(*name_idx - 1).unwrap_or_default();
                    im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0) + 1
                } else {
                    0
                };
                out.extend(write_uleb128(new_name_idx));

                let new_type_idx = if *type_idx != 0 {
                    im.type_restruct_idx.get(&(*type_idx - 1)).copied().unwrap_or(0) + 1
                } else {
                    0
                };
                out.extend(write_uleb128(new_type_idx));
            }
            DebugOpcode::StartLocalExtended { v_reg, name_idx, type_idx, sig_idx } => {
                out.push(0x04);
                out.extend(write_uleb128(*v_reg));
                let new_name_idx = if *name_idx != 0 {
                    let s = im.dex.get_string(*name_idx - 1).unwrap_or_default();
                    im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0) + 1
                } else {
                    0
                };
                out.extend(write_uleb128(new_name_idx));

                let new_type_idx = if *type_idx != 0 {
                    im.type_restruct_idx.get(&(*type_idx - 1)).copied().unwrap_or(0) + 1
                } else {
                    0
                };
                out.extend(write_uleb128(new_type_idx));

                let new_sig_idx = if *sig_idx != 0 {
                    let s = im.dex.get_string(*sig_idx - 1).unwrap_or_default();
                    im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0) + 1
                } else {
                    0
                };
                out.extend(write_uleb128(new_sig_idx));
            }
            DebugOpcode::EndLocal(v_reg) => {
                out.push(0x05);
                out.extend(write_uleb128(*v_reg));
            }
            DebugOpcode::RestartLocal(v_reg) => {
                out.push(0x06);
                out.extend(write_uleb128(*v_reg));
            }
            DebugOpcode::SetFile(name_idx) => {
                out.push(0x09);
                let new_name_idx = if *name_idx != 0 {
                    let s = im.dex.get_string(*name_idx - 1).unwrap_or_default();
                    im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0) + 1
                } else {
                    0
                };
                out.extend(write_uleb128(new_name_idx));
            }
            DebugOpcode::Special(val) => {
                out.push(*val);
            }
        }
    }

    out
}

// ---------------- DexBuilder ----------------

/// Assembles a valid `.dex` binary buffer from remapped and hollowed components.
pub struct DexBuilder<'a> {
    pub im: &'a DexIndexMapper<'a>,
    pub hlw: &'a DexHollower<'a>,
    pub modified_bytecodes: &'a HashMap<u32, Vec<u8>>,
    pub out: Vec<u8>,
}

impl<'a> DexBuilder<'a> {
    pub fn new(
        im: &'a DexIndexMapper<'a>,
        hlw: &'a DexHollower<'a>,
        modified_bytecodes: &'a HashMap<u32, Vec<u8>>,
    ) -> Self {
        Self {
            im,
            hlw,
            modified_bytecodes,
            out: Vec::new(),
        }
    }

    /// Build and return the final DEX byte array.
    pub fn build(&mut self) -> Vec<u8> {
        self.out.clear();
        self.out.resize(112, 0); // 0x70 header space

        // 1. Write Data Section first
        // String Data
        let mut string_data_offs = Vec::with_capacity(self.im.str_restruct.len());
        for s in &self.im.str_restruct {
            string_data_offs.push(self.out.len() as u32);
            let s_bytes = s.as_bytes();
            // MUTF-8 length approx char count
            self.out.extend(write_uleb128(s.chars().count() as u32));
            self.out.extend_from_slice(s_bytes);
            self.out.push(0);
        }

        // Type Lists (Interfaces & Protos)
        let mut proto_param_offs = Vec::with_capacity(self.im.proto_restruct.len());
        align_to(&mut self.out, 4);

        for proto in &self.im.proto_restruct {
            let params = &proto[3..];
            if params.is_empty() {
                proto_param_offs.push(0u32);
            } else {
                align_to(&mut self.out, 4);
                proto_param_offs.push(self.out.len() as u32);
                self.out.extend_from_slice(&(params.len() as u32).to_le_bytes());
                for &p in params {
                    self.out.extend_from_slice(&(p as u16).to_le_bytes());
                }
            }
        }

        // Interface type list
        let mut ifs_off = 0u32;
        if self.hlw.ifs_list_hlw_types.len() > 1 {
            align_to(&mut self.out, 4);
            ifs_off = self.out.len() as u32;
            let ifs_size = self.hlw.ifs_list_hlw_types[0];
            self.out.extend_from_slice(&ifs_size.to_le_bytes());
            for &t in &self.hlw.ifs_list_hlw_types[1..] {
                let new_t = self.im.type_restruct_idx.get(&t).copied().unwrap_or(0) as u16;
                self.out.extend_from_slice(&new_t.to_le_bytes());
            }
        }

        // Annotations
        let mut annotation_item_offs: HashMap<u32, u32> = HashMap::new();
        let mut annotation_set_offs: HashMap<u32, u32> = HashMap::new();
        let mut annotation_set_ref_offs: HashMap<u32, u32> = HashMap::new();
        let mut annotation_dir_off = 0u32;

        if let Some(ref anno_dir) = self.hlw.annotation_directory {
            let mut sorted_items: Vec<(&u32, &AnnotationItem)> = self.hlw.annotation_items.iter().collect();
            sorted_items.sort_by_key(|(k, _)| **k);
            for (old_off, item) in sorted_items {
                annotation_item_offs.insert(*old_off, self.out.len() as u32);
                let built = rebuild_annotation_item(item, self.im);
                self.out.extend(built);
            }

            align_to(&mut self.out, 4);
            let mut sorted_sets: Vec<(&u32, &crate::core::dex::constructor::AnnotationSet)> = self.hlw.annotation_sets.iter().collect();
            sorted_sets.sort_by_key(|(k, _)| **k);
            for (old_off, anno_set) in sorted_sets {
                annotation_set_offs.insert(*old_off, self.out.len() as u32);
                let mut items = anno_set.items.clone();
                items.sort_by_key(|item_off| {
                    if let Some(item) = self.hlw.annotation_items.get(item_off) {
                        self.im.type_restruct_idx.get(&item.annotation.type_idx).copied().unwrap_or(0)
                    } else {
                        0
                    }
                });
                self.out.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for item_off in items {
                    let off = annotation_item_offs.get(&item_off).copied().unwrap_or(0);
                    self.out.extend_from_slice(&off.to_le_bytes());
                }
            }

            align_to(&mut self.out, 4);
            let mut sorted_refs: Vec<(&u32, &Vec<u32>)> = self.hlw.annotation_set_refs.iter().collect();
            sorted_refs.sort_by_key(|(k, _)| **k);
            for (old_off, refs) in sorted_refs {
                annotation_set_ref_offs.insert(*old_off, self.out.len() as u32);
                self.out.extend_from_slice(&(refs.len() as u32).to_le_bytes());
                for set_off in refs {
                    let off = annotation_set_offs.get(set_off).copied().unwrap_or(0);
                    self.out.extend_from_slice(&off.to_le_bytes());
                }
            }

            align_to(&mut self.out, 4);
            annotation_dir_off = self.out.len() as u32;

            let mut field_annotations: Vec<(u32, u32)> = anno_dir.field_annotations
                .iter()
                .filter_map(|(f_idx, set_off)| {
                    self.im.field_restruct_idx.get(f_idx).map(|&new_idx| (new_idx, *set_off))
                })
                .collect();
            field_annotations.sort_by_key(|(f_idx, _)| *f_idx);

            let mut method_annotations: Vec<(u32, u32)> = anno_dir.method_annotations
                .iter()
                .filter_map(|(m_idx, set_off)| {
                    self.im.method_restruct_idx.get(m_idx).map(|&new_idx| (new_idx, *set_off))
                })
                .collect();
            method_annotations.sort_by_key(|(m_idx, _)| *m_idx);

            let mut parameter_annotations: Vec<(u32, u32)> = anno_dir.parameter_annotations
                .iter()
                .filter_map(|(m_idx, ref_off)| {
                    self.im.method_restruct_idx.get(m_idx).map(|&new_idx| (new_idx, *ref_off))
                })
                .collect();
            parameter_annotations.sort_by_key(|(m_idx, _)| *m_idx);

            let class_set_off = annotation_set_offs.get(&anno_dir.class_annotations_off).copied().unwrap_or(0);
            self.out.extend_from_slice(&class_set_off.to_le_bytes());
            self.out.extend_from_slice(&(field_annotations.len() as u32).to_le_bytes());
            self.out.extend_from_slice(&(method_annotations.len() as u32).to_le_bytes());
            self.out.extend_from_slice(&(parameter_annotations.len() as u32).to_le_bytes());

            for (field_idx, set_off) in field_annotations {
                self.out.extend_from_slice(&field_idx.to_le_bytes());
                let off = annotation_set_offs.get(&set_off).copied().unwrap_or(0);
                self.out.extend_from_slice(&off.to_le_bytes());
            }
            for (method_idx, set_off) in method_annotations {
                self.out.extend_from_slice(&method_idx.to_le_bytes());
                let off = annotation_set_offs.get(&set_off).copied().unwrap_or(0);
                self.out.extend_from_slice(&off.to_le_bytes());
            }
            for (method_idx, ref_off) in parameter_annotations {
                self.out.extend_from_slice(&method_idx.to_le_bytes());
                let off = annotation_set_ref_offs.get(&ref_off).copied().unwrap_or(0);
                self.out.extend_from_slice(&off.to_le_bytes());
            }
        }

        // Static values
        let mut static_values_off = 0u32;
        if let Some(ref elements) = self.hlw.static_values_elements {
            align_to(&mut self.out, 4);
            static_values_off = self.out.len() as u32;
            let built = rebuild_encoded_array(elements, self.im);
            self.out.extend(built);
        }

        // Code items and debug info
        let mut code_item_offs: HashMap<u32, u32> = HashMap::new();
        let mut debug_info_offs: Vec<u32> = Vec::new();
        let mut method_to_debug_off: HashMap<u32, u32> = HashMap::new();

        let mut sorted_methods = self.im.methods_obj.clone();
        sorted_methods.sort_by_key(|m| self.im.method_restruct_idx.get(&m.index).copied().unwrap_or(0));

        // First, write all debug info
        for method in &sorted_methods {
            if method.code_offset() == 0 {
                continue;
            }
            if let Some(debug_item) = self.hlw.debug_info_items.get(&method.index) {
                let debug_off = self.out.len() as u32;
                method_to_debug_off.insert(method.index, debug_off);
                debug_info_offs.push(debug_off);
                let built = rebuild_debug_info(debug_item, self.im);
                self.out.extend(built);
            }
        }

        // Then, write all code items
        for method in &sorted_methods {
            if method.code_offset() == 0 {
                continue;
            }
            let _debug_info_off = method_to_debug_off.get(&method.index).copied().unwrap_or(0);

            align_to(&mut self.out, 4);
            code_item_offs.insert(method.index, self.out.len() as u32);

            let empty_info = (Vec::new(), None, 0u16);
            let code_item_info = self.hlw.code_item_hlws.get(&method.index).unwrap_or(&empty_info);
            let orig_header = &code_item_info.0;
            let try_item_bytes = &code_item_info.1;
            let tries_size = code_item_info.2;

            let fallback_header;
            let header_slice = if orig_header.len() == 16 {
                orig_header.as_slice()
            } else {
                let aligned_val = ((method.code_offset() + 3) & !3) as usize;
                if aligned_val + 16 <= self.hlw.dex_buffer.len() {
                    fallback_header = self.hlw.dex_buffer[aligned_val..aligned_val + 16].to_vec();
                } else {
                    fallback_header = vec![0u8; 16];
                }
                fallback_header.as_slice()
            };

            let empty_bc = Vec::new();
            let bc = self.modified_bytecodes.get(&method.index).map(|v| v.as_slice())
                .unwrap_or_else(|| method.bytecode(self.hlw.dex_buffer));
            let insns_size = bc.len() / 2;

            if header_slice.len() == 16 {
                let catch_handler_list = self.hlw.code_item_metadata_hlws.get(&method.index)
                    .and_then(|m| m.1.as_ref());

                self.out.extend_from_slice(header_slice);
                self.out.extend_from_slice(bc);

                if tries_size > 0 {
                    if (insns_size & 1) != 0 {
                        self.out.extend_from_slice(&[0u8, 0u8]); // 2-byte alignment pad
                    }

                    if let Some(ch_list) = catch_handler_list {
                        let mut new_handlers_bytes = Vec::new();
                        let mut old_to_new_offset: HashMap<u32, u32> = HashMap::new();
                        new_handlers_bytes.extend(write_uleb128(ch_list.count));

                        for handler in &ch_list.handlers {
                            old_to_new_offset.insert(handler.old_off, new_handlers_bytes.len() as u32);
                            new_handlers_bytes.extend(write_sleb128(handler.size));

                            for &(t_idx, addr) in &handler.type_addr_pairs {
                                new_handlers_bytes.extend(write_uleb128(t_idx));
                                new_handlers_bytes.extend(write_uleb128(addr));
                            }
                            if handler.size <= 0 {
                                if let Some(catch_all_addr) = handler.catch_all_addr {
                                    new_handlers_bytes.extend(write_uleb128(catch_all_addr));
                                }
                            }
                        }

                        let mut new_try_item_bytes = Vec::new();
                        if let Some(t_bytes) = try_item_bytes {
                            for j in 0..(tries_size as usize) {
                                let base = j * 8;
                                if base + 8 <= t_bytes.len() {
                                    let old_handler_off = u16::from_le_bytes([t_bytes[base + 6], t_bytes[base + 7]]) as u32;
                                    let new_handler_off = old_to_new_offset.get(&old_handler_off).copied().unwrap_or(old_handler_off) as u16;

                                    new_try_item_bytes.extend_from_slice(&t_bytes[base..base + 6]);
                                    new_try_item_bytes.extend_from_slice(&new_handler_off.to_le_bytes());
                                }
                            }
                        }

                        self.out.extend(new_try_item_bytes);
                        self.out.extend(new_handlers_bytes);
                    }
                }
            }
        }

        // Class Data Item
        let mut class_data_off = 0u32;
        if !self.im.fields_obj.is_empty() || !self.im.methods_obj.is_empty() {
            class_data_off = self.out.len() as u32;

            let mut s_f: Vec<_> = self.im.fields_obj.iter().filter(|f| f.is_static).cloned().collect();
            s_f.sort_by_key(|f| self.im.field_restruct_idx.get(&f.index).copied().unwrap_or(0));

            let mut i_f: Vec<_> = self.im.fields_obj.iter().filter(|f| !f.is_static).cloned().collect();
            i_f.sort_by_key(|f| self.im.field_restruct_idx.get(&f.index).copied().unwrap_or(0));

            let mut d_m: Vec<_> = self.im.methods_obj.iter().filter(|m| !m.is_virtual).cloned().collect();
            d_m.sort_by_key(|m| self.im.method_restruct_idx.get(&m.index).copied().unwrap_or(0));

            let mut v_m: Vec<_> = self.im.methods_obj.iter().filter(|m| m.is_virtual).cloned().collect();
            v_m.sort_by_key(|m| self.im.method_restruct_idx.get(&m.index).copied().unwrap_or(0));

            self.out.extend(write_uleb128(s_f.len() as u32));
            self.out.extend(write_uleb128(i_f.len() as u32));
            self.out.extend(write_uleb128(d_m.len() as u32));
            self.out.extend(write_uleb128(v_m.len() as u32));

            let mut last_idx = 0u32;
            for f in &s_f {
                let new_idx = self.im.field_restruct_idx.get(&f.index).copied().unwrap_or(0);
                self.out.extend(write_uleb128(new_idx.wrapping_sub(last_idx)));
                last_idx = new_idx;
                self.out.extend(write_uleb128(f.access_flags));
            }

            last_idx = 0;
            for f in &i_f {
                let new_idx = self.im.field_restruct_idx.get(&f.index).copied().unwrap_or(0);
                self.out.extend(write_uleb128(new_idx.wrapping_sub(last_idx)));
                last_idx = new_idx;
                self.out.extend(write_uleb128(f.access_flags));
            }

            last_idx = 0;
            for m in &d_m {
                let new_idx = self.im.method_restruct_idx.get(&m.index).copied().unwrap_or(0);
                self.out.extend(write_uleb128(new_idx.wrapping_sub(last_idx)));
                last_idx = new_idx;
                self.out.extend(write_uleb128(m.access_flags));
                let c_off = code_item_offs.get(&m.index).copied().unwrap_or(0);
                self.out.extend(write_uleb128(c_off));
            }

            last_idx = 0;
            for m in &v_m {
                let new_idx = self.im.method_restruct_idx.get(&m.index).copied().unwrap_or(0);
                self.out.extend(write_uleb128(new_idx.wrapping_sub(last_idx)));
                last_idx = new_idx;
                self.out.extend(write_uleb128(m.access_flags));
                let c_off = code_item_offs.get(&m.index).copied().unwrap_or(0);
                self.out.extend(write_uleb128(c_off));
            }
        }

        // Now write IDs
        align_to(&mut self.out, 4);

        // String IDs
        let string_ids_off = self.out.len() as u32;
        for &s_off in &string_data_offs {
            self.out.extend_from_slice(&s_off.to_le_bytes());
        }

        // Type IDs
        let type_ids_off = self.out.len() as u32;
        for &desc_idx in &self.im.type_restruct {
            self.out.extend_from_slice(&desc_idx.to_le_bytes());
        }

        // Proto IDs
        let proto_ids_off = self.out.len() as u32;
        for (i, proto) in self.im.proto_restruct.iter().enumerate() {
            let short_idx = proto[0];
            let ret_idx = proto[1];
            let param_off = proto_param_offs.get(i).copied().unwrap_or(0);
            self.out.extend_from_slice(&short_idx.to_le_bytes());
            self.out.extend_from_slice(&ret_idx.to_le_bytes());
            self.out.extend_from_slice(&param_off.to_le_bytes());
        }

        // Field IDs
        let field_ids_off = self.out.len() as u32;
        for fld in &self.im.field_restruct {
            let clz_idx = fld[0] as u16;
            let type_idx = fld[1] as u16;
            let name_idx = fld[2];
            self.out.extend_from_slice(&clz_idx.to_le_bytes());
            self.out.extend_from_slice(&type_idx.to_le_bytes());
            self.out.extend_from_slice(&name_idx.to_le_bytes());
        }

        // Method IDs
        let method_ids_off = self.out.len() as u32;
        for mth in &self.im.method_restruct {
            let clz_idx = mth[0] as u16;
            let proto_idx = mth[1] as u16;
            let name_idx = mth[2];
            self.out.extend_from_slice(&clz_idx.to_le_bytes());
            self.out.extend_from_slice(&proto_idx.to_le_bytes());
            self.out.extend_from_slice(&name_idx.to_le_bytes());
        }

        // Class Defs
        let class_defs_off = self.out.len() as u32;
        let orig_clz_type = self.hlw.clz_def_hlw_types.get(&0).copied().unwrap_or(0xffff_ffff);
        let clz_idx = self.im.type_restruct_idx.get(&orig_clz_type).copied().unwrap_or(0);

        let acc_flags = u32::from_le_bytes([
            self.hlw.clz_raw_byte[4],
            self.hlw.clz_raw_byte[5],
            self.hlw.clz_raw_byte[6],
            self.hlw.clz_raw_byte[7],
        ]);

        let orig_super = u32::from_le_bytes([
            self.hlw.clz_raw_byte[8],
            self.hlw.clz_raw_byte[9],
            self.hlw.clz_raw_byte[10],
            self.hlw.clz_raw_byte[11],
        ]);
        let super_idx = self.im.type_restruct_idx.get(&orig_super).copied().unwrap_or(0xffff_ffff);

        let orig_src = u32::from_le_bytes([
            self.hlw.clz_raw_byte[16],
            self.hlw.clz_raw_byte[17],
            self.hlw.clz_raw_byte[18],
            self.hlw.clz_raw_byte[19],
        ]);
        let src_idx = if orig_src != 0xffff_ffff {
            let s = self.im.dex.get_string(orig_src).unwrap_or_default();
            self.im.str_restruct_idx.get(s.as_ref()).copied().unwrap_or(0xffff_ffff)
        } else {
            0xffff_ffff
        };

        self.out.extend_from_slice(&clz_idx.to_le_bytes());
        self.out.extend_from_slice(&acc_flags.to_le_bytes());
        self.out.extend_from_slice(&super_idx.to_le_bytes());
        self.out.extend_from_slice(&ifs_off.to_le_bytes());
        self.out.extend_from_slice(&src_idx.to_le_bytes());
        self.out.extend_from_slice(&annotation_dir_off.to_le_bytes());
        self.out.extend_from_slice(&class_data_off.to_le_bytes());
        self.out.extend_from_slice(&static_values_off.to_le_bytes());

        // Map List
        align_to(&mut self.out, 4);
        let map_list_off = self.out.len() as u32;

        let mut map_items: Vec<(u16, u32, u32)> = Vec::new();
        map_items.push((0x0000, 1, 0)); // Header
        if !self.im.str_restruct.is_empty() {
            map_items.push((0x0001, self.im.str_restruct.len() as u32, string_ids_off));
            map_items.push((0x2002, self.im.str_restruct.len() as u32, string_data_offs[0]));
        }
        if !self.im.type_restruct.is_empty() {
            map_items.push((0x0002, self.im.type_restruct.len() as u32, type_ids_off));
        }
        if !self.im.proto_restruct.is_empty() {
            map_items.push((0x0003, self.im.proto_restruct.len() as u32, proto_ids_off));
        }
        if !self.im.field_restruct.is_empty() {
            map_items.push((0x0004, self.im.field_restruct.len() as u32, field_ids_off));
        }
        if !self.im.method_restruct.is_empty() {
            map_items.push((0x0005, self.im.method_restruct.len() as u32, method_ids_off));
        }
        map_items.push((0x0006, 1, class_defs_off));

        // TYPE_TYPE_LIST (0x1001)
        let mut type_list_count = 0u32;
        let mut first_type_list_off = 0u32;
        if ifs_off > 0 {
            type_list_count += 1;
            first_type_list_off = ifs_off;
        }
        let valid_proto_param_offs: Vec<u32> = proto_param_offs.iter().copied().filter(|&off| off > 0).collect();
        if !valid_proto_param_offs.is_empty() {
            type_list_count += valid_proto_param_offs.len() as u32;
            let min_proto_off = *valid_proto_param_offs.iter().min().unwrap();
            if first_type_list_off == 0 || min_proto_off < first_type_list_off {
                first_type_list_off = min_proto_off;
            }
        }
        if type_list_count > 0 {
            map_items.push((0x1001, type_list_count, first_type_list_off));
        }

        if !annotation_set_ref_offs.is_empty() {
            let min_off = *annotation_set_ref_offs.values().min().unwrap();
            map_items.push((0x1002, annotation_set_ref_offs.len() as u32, min_off));
        }
        if !annotation_set_offs.is_empty() {
            let min_off = *annotation_set_offs.values().min().unwrap();
            map_items.push((0x1003, annotation_set_offs.len() as u32, min_off));
        }
        if annotation_dir_off > 0 {
            map_items.push((0x2006, 1, annotation_dir_off));
        }
        if !annotation_item_offs.is_empty() {
            let min_off = *annotation_item_offs.values().min().unwrap();
            map_items.push((0x2004, annotation_item_offs.len() as u32, min_off));
        }

        if class_data_off > 0 {
            map_items.push((0x2000, 1, class_data_off));
        }
        if !code_item_offs.is_empty() {
            let min_off = *code_item_offs.values().min().unwrap();
            map_items.push((0x2001, code_item_offs.len() as u32, min_off));
        }

        if !debug_info_offs.is_empty() {
            let min_off = *debug_info_offs.iter().min().unwrap();
            map_items.push((0x2003, debug_info_offs.len() as u32, min_off));
        }

        if static_values_off > 0 {
            map_items.push((0x2005, 1, static_values_off));
        }

        map_items.sort_by_key(|x| x.2);
        map_items.push((0x1000, 1, map_list_off)); // Map list itself

        self.out.extend_from_slice(&(map_items.len() as u32).to_le_bytes());
        for (item_type, size, offset) in map_items {
            self.out.extend_from_slice(&item_type.to_le_bytes());
            self.out.extend_from_slice(&0u16.to_le_bytes()); // unused
            self.out.extend_from_slice(&size.to_le_bytes());
            self.out.extend_from_slice(&offset.to_le_bytes());
        }

        let file_size = self.out.len() as u32;

        // Header Patching
        // magic
        self.out[0..8].copy_from_slice(b"dex\n035\0");
        // file_size
        self.out[32..36].copy_from_slice(&file_size.to_le_bytes());
        // header_size
        self.out[36..40].copy_from_slice(&0x70u32.to_le_bytes());
        // endian_tag
        self.out[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        // map_off
        self.out[52..56].copy_from_slice(&map_list_off.to_le_bytes());
        // string_ids
        self.out[56..60].copy_from_slice(&(self.im.str_restruct.len() as u32).to_le_bytes());
        self.out[60..64].copy_from_slice(&string_ids_off.to_le_bytes());
        // type_ids
        self.out[64..68].copy_from_slice(&(self.im.type_restruct.len() as u32).to_le_bytes());
        self.out[68..72].copy_from_slice(&type_ids_off.to_le_bytes());
        // proto_ids
        self.out[72..76].copy_from_slice(&(self.im.proto_restruct.len() as u32).to_le_bytes());
        self.out[76..80].copy_from_slice(&proto_ids_off.to_le_bytes());
        // field_ids
        self.out[80..84].copy_from_slice(&(self.im.field_restruct.len() as u32).to_le_bytes());
        self.out[84..88].copy_from_slice(&field_ids_off.to_le_bytes());
        // method_ids
        self.out[88..92].copy_from_slice(&(self.im.method_restruct.len() as u32).to_le_bytes());
        self.out[92..96].copy_from_slice(&method_ids_off.to_le_bytes());
        // class_defs
        self.out[96..100].copy_from_slice(&1u32.to_le_bytes());
        self.out[100..104].copy_from_slice(&class_defs_off.to_le_bytes());
        // data_size, data_off
        self.out[104..108].copy_from_slice(&(file_size - 0x70).to_le_bytes());
        self.out[108..112].copy_from_slice(&0x70u32.to_le_bytes());

        // signature
        self.out[12..32].fill(0);
        // checksum
        self.out[8..12].fill(0);

        self.out.clone()
    }
}
