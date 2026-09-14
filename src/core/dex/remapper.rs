//! DEX index remapping structures and logic.
//!
//! Ported from `src/asc_core/core/dex/dex_remapper.py`.

use std::collections::HashMap;
use crate::core::tinydex::{Dex, ClassItem, FieldItem, MethodItem, TypeKind, PrimitiveType};
use crate::core::dex::constructor::DexHollower;

/// Helper operator for extracting raw table entries directly from the DEX buffer.
#[derive(Debug, Clone, Copy)]
pub struct DexOperator<'a> {
    pub buf: &'a [u8],
    pub string_ids_off: u32,
    pub type_ids_off: u32,
    pub proto_ids_off: u32,
    pub field_ids_off: u32,
    pub method_ids_off: u32,
}

impl<'a> DexOperator<'a> {
    pub fn new(dex: &Dex<'a>, buf: &'a [u8]) -> Self {
        Self {
            buf,
            string_ids_off: dex.header.strings.0,
            type_ids_off: dex.header.types.0,
            proto_ids_off: dex.header.prototypes.0,
            field_ids_off: dex.header.fields.0,
            method_ids_off: dex.header.methods.0,
        }
    }

    #[inline]
    pub fn get_type_descidx(&self, type_idx: u32) -> u32 {
        let offset = (self.type_ids_off as usize) + (type_idx as usize) * 4;
        if offset + 4 <= self.buf.len() {
            u32::from_le_bytes([
                self.buf[offset],
                self.buf[offset + 1],
                self.buf[offset + 2],
                self.buf[offset + 3],
            ])
        } else {
            0
        }
    }

    #[inline]
    pub fn get_proto_shortidx(&self, proto_idx: u32) -> u32 {
        let offset = (self.proto_ids_off as usize) + (proto_idx as usize) * 12;
        if offset + 4 <= self.buf.len() {
            u32::from_le_bytes([
                self.buf[offset],
                self.buf[offset + 1],
                self.buf[offset + 2],
                self.buf[offset + 3],
            ])
        } else {
            0
        }
    }

    #[inline]
    pub fn get_proto_rettypeidx(&self, proto_idx: u32) -> u32 {
        let offset = (self.proto_ids_off as usize) + (proto_idx as usize) * 12 + 4;
        if offset + 4 <= self.buf.len() {
            u32::from_le_bytes([
                self.buf[offset],
                self.buf[offset + 1],
                self.buf[offset + 2],
                self.buf[offset + 3],
            ])
        } else {
            0
        }
    }

    #[inline]
    pub fn get_method_proto_idx(&self, method_idx: u32) -> u16 {
        let offset = (self.method_ids_off as usize) + (method_idx as usize) * 8 + 2;
        if offset + 2 <= self.buf.len() {
            u16::from_le_bytes([self.buf[offset], self.buf[offset + 1]])
        } else {
            0
        }
    }
}

/// Mapper input container tracking referenced indices per category:
/// "STRING", "TYPE", "FIELD", "METHOD"
#[derive(Debug, Clone, Default)]
pub struct IndexHandlerMapper {
    pub strings: Vec<u32>,
    pub types: Vec<u32>,
    pub fields: Vec<u32>,
    pub methods: Vec<u32>,
}

/// Remaps DEX IDs from original DEX into compact, continuous ID spaces for the hollowed class.
pub struct DexIndexMapper<'a> {
    pub mapper: IndexHandlerMapper,
    pub dex: Dex<'a>,
    pub dex_buffer: &'a [u8],
    pub dex_operator: DexOperator<'a>,

    // Class and hollower references
    pub class_obj: Option<ClassItem<'a>>,
    pub methods_obj: Vec<MethodItem<'a>>,
    pub fields_obj: Vec<FieldItem<'a>>,

    // Restructured tables
    pub str_restruct: Vec<String>,
    pub str_restruct_pos: u32,
    pub str_restruct_idx: HashMap<String, u32>,

    pub type_restruct: Vec<u32>,
    pub type_restruct_pos: u32,
    pub type_restruct_idx: HashMap<u32, u32>,

    pub proto_restruct: Vec<Vec<u32>>,
    pub proto_restruct_pos: u32,
    pub proto_restruct_idx: HashMap<u32, u32>,

    pub field_restruct: Vec<[u32; 3]>,
    pub field_restruct_pos: u32,
    pub field_restruct_idx: HashMap<u32, u32>,

    pub method_restruct: Vec<[u32; 3]>,
    pub method_restruct_pos: u32,
    pub method_restruct_idx: HashMap<u32, u32>,

    // Primitive data type mapping
    pub stridx_data_types: HashMap<PrimitiveType, u32>,
    pub typeidx_data_types: HashMap<PrimitiveType, u32>,
}

impl<'a> DexIndexMapper<'a> {
    pub fn new(mapper: IndexHandlerMapper, dex: Dex<'a>, dex_buffer: &'a [u8]) -> Self {
        let dex_operator = DexOperator::new(&dex, dex_buffer);
        Self {
            mapper,
            dex,
            dex_buffer,
            dex_operator,
            class_obj: None,
            methods_obj: Vec::new(),
            fields_obj: Vec::new(),
            str_restruct: Vec::new(),
            str_restruct_pos: 0,
            str_restruct_idx: HashMap::new(),
            type_restruct: Vec::new(),
            type_restruct_pos: 0,
            type_restruct_idx: HashMap::new(),
            proto_restruct: Vec::new(),
            proto_restruct_pos: 0,
            proto_restruct_idx: HashMap::new(),
            field_restruct: Vec::new(),
            field_restruct_pos: 0,
            field_restruct_idx: HashMap::new(),
            method_restruct: Vec::new(),
            method_restruct_pos: 0,
            method_restruct_idx: HashMap::new(),
            stridx_data_types: HashMap::new(),
            typeidx_data_types: HashMap::new(),
        }
    }

    pub fn set_class(&mut self, clz: ClassItem<'a>) {
        self.methods_obj = clz.methods.clone();
        self.fields_obj = clz.fields.clone();
        self.class_obj = Some(clz);
    }

    pub fn add_str_restruct(&mut self, string: &str) -> u32 {
        if let Some(&idx) = self.str_restruct_idx.get(string) {
            return idx;
        }
        let idx = self.str_restruct_pos;
        self.str_restruct.push(string.to_string());
        self.str_restruct_idx.insert(string.to_string(), idx);
        self.str_restruct_pos += 1;
        idx
    }

    pub fn add_type_restruct(&mut self, desc_idx: u32, origin_idx: Option<u32>) -> u32 {
        if let Some(orig) = origin_idx {
            if let Some(&idx) = self.type_restruct_idx.get(&orig) {
                return idx;
            }
        }
        let idx = self.type_restruct_pos;
        self.type_restruct.push(desc_idx);
        if let Some(orig) = origin_idx {
            self.type_restruct_idx.insert(orig, idx);
        }
        self.type_restruct_pos += 1;
        idx
    }

    pub fn add_proto_restruct(&mut self, prototype: Vec<u32>, origin_idx: Option<u32>) -> u32 {
        if let Some(orig) = origin_idx {
            if let Some(&idx) = self.proto_restruct_idx.get(&orig) {
                return idx;
            }
        }
        let idx = self.proto_restruct_pos;
        self.proto_restruct.push(prototype);
        if let Some(orig) = origin_idx {
            self.proto_restruct_idx.insert(orig, idx);
        }
        self.proto_restruct_pos += 1;
        idx
    }

    pub fn add_field_restruct(&mut self, field: [u32; 3], origin_idx: Option<u32>) -> u32 {
        if let Some(orig) = origin_idx {
            if let Some(&idx) = self.field_restruct_idx.get(&orig) {
                return idx;
            }
        }
        let idx = self.field_restruct_pos;
        self.field_restruct.push(field);
        if let Some(orig) = origin_idx {
            self.field_restruct_idx.insert(orig, idx);
        }
        self.field_restruct_pos += 1;
        idx
    }

    pub fn add_method_restruct(&mut self, method: [u32; 3], origin_idx: Option<u32>) -> u32 {
        if let Some(orig) = origin_idx {
            if let Some(&idx) = self.method_restruct_idx.get(&orig) {
                return idx;
            }
        }
        let idx = self.method_restruct_pos;
        self.method_restruct.push(method);
        if let Some(orig) = origin_idx {
            self.method_restruct_idx.insert(orig, idx);
        }
        self.method_restruct_pos += 1;
        idx
    }

    pub fn append_origin_type(&mut self, origin_type_idx: u32) -> u32 {
        if let Some(&new_idx) = self.type_restruct_idx.get(&origin_type_idx) {
            return new_idx;
        }
        let origin_desc_idx = self.dex_operator.get_type_descidx(origin_type_idx);
        let s = self.dex.get_string(origin_desc_idx).unwrap_or_default();
        let new_desc_idx = self.add_str_restruct(&s);
        self.add_type_restruct(new_desc_idx, Some(origin_type_idx))
    }

    pub fn append_string_to_types(&mut self, string: &str) -> u32 {
        let desc_idx = self.add_str_restruct(string);
        self.add_type_restruct(desc_idx, None)
    }

    pub fn type_to_descriptor(&self, typ: &crate::core::tinydex::Type<'_>) -> String {
        match typ.kind {
            TypeKind::Primitive => match typ.value {
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Void)) => "V".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Boolean)) => "Z".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Byte)) => "B".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Short)) => "S".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Char)) => "C".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Int)) => "I".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Long)) => "J".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Float)) => "F".to_string(),
                Some(crate::core::tinydex::TypeValue::Primitive(PrimitiveType::Double)) => "D".to_string(),
                _ => "V".to_string(),
            },
            TypeKind::Array => {
                let mut s = "[".repeat(typ.dim);
                if let Some(ref underlying) = typ.underlying_array_type {
                    s.push_str(&self.type_to_descriptor(underlying));
                }
                s
            }
            TypeKind::Class => typ.descriptor.to_string(),
        }
    }

    fn fill_data_types(&mut self) {
        let primitives = [
            (PrimitiveType::Void, "V"),
            (PrimitiveType::Boolean, "Z"),
            (PrimitiveType::Byte, "B"),
            (PrimitiveType::Short, "S"),
            (PrimitiveType::Char, "C"),
            (PrimitiveType::Int, "I"),
            (PrimitiveType::Long, "J"),
            (PrimitiveType::Float, "F"),
            (PrimitiveType::Double, "D"),
        ];

        for (prim, ch) in primitives {
            let str_idx = self.add_str_restruct(ch);
            self.stridx_data_types.insert(prim, str_idx);
            let type_idx = self.add_type_restruct(str_idx, None);
            self.typeidx_data_types.insert(prim, type_idx);
        }
    }

    /// Process remapping of strings, types, fields, methods, hollowed data, and code catch handlers.
    pub fn handle(&mut self, hollower: &mut DexHollower<'a>) {
        // === STRING IDX ===
        for &str_idx in &self.mapper.strings {
            if let Some(s) = self.dex.get_string(str_idx) {
                self.add_str_restruct(&s);
            }
        }

        // === TYPE IDX ===
        for &type_idx in &self.mapper.types {
            self.append_origin_type(type_idx);
        }

        self.fill_data_types();

        // === FIELD IDX ===
        for &origin_field_idx in &self.mapper.fields {
            if self.field_restruct_idx.contains_key(&origin_field_idx) {
                continue;
            }
            if let Some(field_obj) = self.dex.get_field(origin_field_idx) {
                let fld_clz_string = field_obj.class_descriptor(&self.dex).unwrap_or_default();
                let fld_clz_typeidx = self.append_string_to_types(&fld_clz_string);
                let fld_type_string = field_obj.field_type(&self.dex)
                    .map(|t| self.type_to_descriptor(&t))
                    .unwrap_or_default();
                let fld_type_typeidx = self.append_string_to_types(&fld_type_string);
                let fld_name_string = field_obj.name(&self.dex).unwrap_or_default();
                let fld_name_stridx = self.add_str_restruct(&fld_name_string);
                let new_field = [fld_clz_typeidx, fld_type_typeidx, fld_name_stridx];
                self.add_field_restruct(new_field, Some(field_obj.index));
            }
        }

        // === METHOD IDX ===
        for &origin_method_idx in &self.mapper.methods {
            if self.method_restruct_idx.contains_key(&origin_method_idx) {
                continue;
            }
            let origin_proto_idx = self.dex_operator.get_method_proto_idx(origin_method_idx) as u32;
            let short_idx = self.dex_operator.get_proto_shortidx(origin_proto_idx);
            let shorty = self.dex.get_string(short_idx).unwrap_or_default();
            let new_short_idx = self.add_str_restruct(&shorty);

            let rettypeidx = self.dex_operator.get_proto_rettypeidx(origin_proto_idx);
            let new_rettypeidx = self.append_origin_type(rettypeidx);

            if let Some(method) = self.dex.get_method(origin_method_idx) {
                let proto = method.prototype(&self.dex);
                let params = proto.as_ref().map(|p| p.parameters_type(&self.dex)).unwrap_or_default();
                let mut new_prototype = vec![new_short_idx, new_rettypeidx, params.len() as u32];

                for param in &params {
                    if param.kind == TypeKind::Primitive {
                        if let Some(crate::core::tinydex::TypeValue::Primitive(prim)) = param.value {
                            if let Some(&p_idx) = self.typeidx_data_types.get(&prim) {
                                new_prototype.push(p_idx);
                                continue;
                            }
                        }
                    }
                    let param_clz_string = self.type_to_descriptor(param);
                    let type_idx = self.append_string_to_types(&param_clz_string);
                    new_prototype.push(type_idx);
                }
                let new_proto_idx = self.add_proto_restruct(new_prototype, Some(origin_proto_idx));

                let mth_cls_name_string = method.class_descriptor(&self.dex).unwrap_or_default();
                let mth_cls_name_typeidx = self.append_string_to_types(&mth_cls_name_string);
                let mth_name_string = method.name(&self.dex).unwrap_or_default();
                let mth_name_stridx = self.add_str_restruct(&mth_name_string);
                let new_mth = [mth_cls_name_typeidx, new_proto_idx, mth_name_stridx];
                self.add_method_restruct(new_mth, Some(method.index));
            }
        }

        // === CLASS FIELD IDX ===
        let fields_to_process = self.fields_obj.clone();
        for field_obj in &fields_to_process {
            if self.field_restruct_idx.contains_key(&field_obj.index) {
                continue;
            }
            let fld_clz_string = field_obj.class_descriptor(&self.dex).unwrap_or_default();
            let fld_clz_typeidx = self.append_string_to_types(&fld_clz_string);
            let fld_type_string = field_obj.field_type(&self.dex)
                .map(|t| self.type_to_descriptor(&t))
                .unwrap_or_default();
            let fld_type_typeidx = self.append_string_to_types(&fld_type_string);
            let fld_name_string = field_obj.name(&self.dex).unwrap_or_default();
            let fld_name_stridx = self.add_str_restruct(&fld_name_string);
            let new_field = [fld_clz_typeidx, fld_type_typeidx, fld_name_stridx];
            self.add_field_restruct(new_field, Some(field_obj.index));
        }

        // === CLASS METHOD IDX ===
        let methods_to_process = self.methods_obj.clone();
        for method in &methods_to_process {
            if self.method_restruct_idx.contains_key(&method.index) {
                continue;
            }
            let origin_proto_idx = self.dex_operator.get_method_proto_idx(method.index) as u32;
            let short_idx = self.dex_operator.get_proto_shortidx(origin_proto_idx);
            let shorty = self.dex.get_string(short_idx).unwrap_or_default();
            let new_short_idx = self.add_str_restruct(&shorty);

            let rettypeidx = self.dex_operator.get_proto_rettypeidx(origin_proto_idx);
            let new_rettypeidx = self.append_origin_type(rettypeidx);

            let proto = method.prototype(&self.dex);
            let params = proto.as_ref().map(|p| p.parameters_type(&self.dex)).unwrap_or_default();
            let mut new_prototype = vec![new_short_idx, new_rettypeidx, params.len() as u32];

            for param in &params {
                if param.kind == TypeKind::Primitive {
                    if let Some(crate::core::tinydex::TypeValue::Primitive(prim)) = param.value {
                        if let Some(&p_idx) = self.typeidx_data_types.get(&prim) {
                            new_prototype.push(p_idx);
                            continue;
                        }
                    }
                }
                let param_clz_string = self.type_to_descriptor(param);
                let type_idx = self.append_string_to_types(&param_clz_string);
                new_prototype.push(type_idx);
            }
            let new_proto_idx = self.add_proto_restruct(new_prototype, Some(origin_proto_idx));

            let mth_cls_name_string = method.class_descriptor(&self.dex).unwrap_or_default();
            let mth_cls_name_typeidx = self.append_string_to_types(&mth_cls_name_string);
            let mth_name_string = method.name(&self.dex).unwrap_or_default();
            let mth_name_stridx = self.add_str_restruct(&mth_name_string);
            let new_mth = [mth_cls_name_typeidx, new_proto_idx, mth_name_stridx];
            self.add_method_restruct(new_mth, Some(method.index));
        }

        // === CLASS DEF IDX ===
        if let Some(&src_idx) = hollower.clz_def_hlw_strs.get(&0x10) {
            if src_idx != 0xffff_ffff {
                if let Some(src_str) = self.dex.get_string(src_idx) {
                    self.add_str_restruct(&src_str);
                }
            }
        }
        if let Some(&clz_idx) = hollower.clz_def_hlw_types.get(&0) {
            if clz_idx != 0xffff_ffff {
                self.append_origin_type(clz_idx);
            }
        }
        if let Some(&super_idx) = hollower.clz_def_hlw_types.get(&0x8) {
            if super_idx != 0xffff_ffff {
                self.append_origin_type(super_idx);
            }
        }

        let ifs_list = hollower.ifs_list_hlw_types.clone();
        if ifs_list.len() > 1 {
            for &ifs_idx in &ifs_list[1..] {
                self.append_origin_type(ifs_idx);
            }
        }

        let hlw_strs_clone = hollower.hlw_strs.clone();
        for s_idx in hlw_strs_clone {
            if s_idx != 0xffff_ffff && (s_idx as usize) < self.dex.strings_count() {
                if let Some(s) = self.dex.get_string(s_idx) {
                    self.add_str_restruct(&s);
                }
            }
        }

        let hlw_types_clone = hollower.hlw_types.clone();
        for t_idx in hlw_types_clone {
            if t_idx != 0xffff_ffff {
                self.append_origin_type(t_idx);
            }
        }

        let hlw_fields_clone = hollower.hlw_fields.clone();
        for f_idx in hlw_fields_clone {
            if f_idx != 0xffff_ffff && !self.field_restruct_idx.contains_key(&f_idx) {
                if let Some(field_obj) = self.dex.get_field(f_idx) {
                    let fld_clz_string = field_obj.class_descriptor(&self.dex).unwrap_or_default();
                    let fld_clz_typeidx = self.append_string_to_types(&fld_clz_string);
                    let fld_type_string = field_obj.field_type(&self.dex)
                        .map(|t| self.type_to_descriptor(&t))
                        .unwrap_or_default();
                    let fld_type_typeidx = self.append_string_to_types(&fld_type_string);
                    let fld_name_string = field_obj.name(&self.dex).unwrap_or_default();
                    let fld_name_stridx = self.add_str_restruct(&fld_name_string);
                    let new_field = [fld_clz_typeidx, fld_type_typeidx, fld_name_stridx];
                    self.add_field_restruct(new_field, Some(field_obj.index));
                }
            }
        }

        let hlw_methods_clone = hollower.hlw_methods.clone();
        for m_idx in hlw_methods_clone {
            if m_idx != 0xffff_ffff && !self.method_restruct_idx.contains_key(&m_idx) {
                let origin_proto_idx = self.dex_operator.get_method_proto_idx(m_idx) as u32;
                let short_idx = self.dex_operator.get_proto_shortidx(origin_proto_idx);
                let shorty = self.dex.get_string(short_idx).unwrap_or_default();
                let new_short_idx = self.add_str_restruct(&shorty);

                let rettypeidx = self.dex_operator.get_proto_rettypeidx(origin_proto_idx);
                let new_rettypeidx = self.append_origin_type(rettypeidx);

                if let Some(method) = self.dex.get_method(m_idx) {
                    let proto = method.prototype(&self.dex);
                    let params = proto.as_ref().map(|p| p.parameters_type(&self.dex)).unwrap_or_default();
                    let mut new_prototype = vec![new_short_idx, new_rettypeidx, params.len() as u32];

                    for param in &params {
                        if param.kind == TypeKind::Primitive {
                            if let Some(crate::core::tinydex::TypeValue::Primitive(prim)) = param.value {
                                if let Some(&p_idx) = self.typeidx_data_types.get(&prim) {
                                    new_prototype.push(p_idx);
                                    continue;
                                }
                            }
                        }
                        let param_clz_string = self.type_to_descriptor(param);
                        let type_idx = self.append_string_to_types(&param_clz_string);
                        new_prototype.push(type_idx);
                    }
                    let new_proto_idx = self.add_proto_restruct(new_prototype, Some(origin_proto_idx));

                    let mth_cls_name_string = method.class_descriptor(&self.dex).unwrap_or_default();
                    let mth_cls_name_typeidx = self.append_string_to_types(&mth_cls_name_string);
                    let mth_name_string = method.name(&self.dex).unwrap_or_default();
                    let mth_name_stridx = self.add_str_restruct(&mth_name_string);
                    let new_mth = [mth_cls_name_typeidx, new_proto_idx, mth_name_stridx];
                    self.add_method_restruct(new_mth, Some(method.index));
                }
            }
        }

        // === CODE ITEM TRY_ITEM CATCH HANDLER IDX ===
        for metadata in hollower.code_item_metadata_hlws.values_mut() {
            if let Some(ref mut catch_handler_list) = metadata.1 {
                for handler in catch_handler_list.handlers.iter_mut() {
                    for pair in handler.type_addr_pairs.iter_mut() {
                        let old_type_idx = pair.0;
                        let new_type_idx = self.append_origin_type(old_type_idx);
                        pair.0 = new_type_idx;
                    }
                }
            }
        }
    }
}
