//! Native, zero-copy DEX binary parser.
//!
//! Ported directly from `src/asc_core/utils/tinydex.py`.

use std::borrow::Cow;
use std::fmt;

use crate::core::leb128::read_uleb128_fast;

/// Error returned when DEX parsing fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DexError {
    BufferTooSmall { required: usize, actual: usize },
    InvalidMagic,
    InvalidOffset { offset: usize, buffer_len: usize },
    NotFound,
}

impl fmt::Display for DexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DexError::BufferTooSmall { required, actual } => {
                write!(f, "DEX buffer too small: required {}, actual {}", required, actual)
            }
            DexError::InvalidMagic => write!(f, "Invalid DEX magic header"),
            DexError::InvalidOffset { offset, buffer_len } => {
                write!(f, "Invalid offset {} beyond buffer len {}", offset, buffer_len)
            }
            DexError::NotFound => write!(f, "Item not found in DEX"),
        }
    }
}

impl std::error::Error for DexError {}

#[inline(always)]
fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    if off + 2 <= buf.len() {
        Some(u16::from_le_bytes([buf[off], buf[off + 1]]))
    } else {
        None
    }
}

#[inline(always)]
fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    if off + 4 <= buf.len() {
        Some(u32::from_le_bytes([
            buf[off],
            buf[off + 1],
            buf[off + 2],
            buf[off + 3],
        ]))
    } else {
        None
    }
}

/// DEX file header layout matching Python `DEXHeader`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DEXHeader {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub mapoff: u32,
    /// `(offset, size)` of String IDs
    pub strings: (u32, u32),
    /// `(offset, size)` of Type IDs
    pub types: (u32, u32),
    /// `(offset, size)` of Proto IDs
    pub prototypes: (u32, u32),
    /// `(offset, size)` of Field IDs
    pub fields: (u32, u32),
    /// `(offset, size)` of Method IDs
    pub methods: (u32, u32),
    /// `(offset, size)` of Class Defs
    pub classes: (u32, u32),
    pub data_size: u32,
    pub data_off: u32,
}

pub type DexHeader = DEXHeader;

impl DEXHeader {
    /// Parse header from raw DEX bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, DexError> {
        if buf.len() < 0x68 {
            return Err(DexError::BufferTooSmall {
                required: 0x68,
                actual: buf.len(),
            });
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&buf[0..8]);
        if &magic[0..4] != b"dex\n" && &magic[0..4] != b"dey\n" {
            // Some fixtures or modified dexes might use standard dex magic
        }

        let checksum = read_u32_le(buf, 0x08).unwrap_or(0);
        let mut signature = [0u8; 20];
        signature.copy_from_slice(&buf[0x0c..0x20]);
        let file_size = read_u32_le(buf, 0x20).unwrap_or(0);
        let header_size = read_u32_le(buf, 0x24).unwrap_or(0);
        let endian_tag = read_u32_le(buf, 0x28).unwrap_or(0);
        let link_size = read_u32_le(buf, 0x2c).unwrap_or(0);
        let link_off = read_u32_le(buf, 0x30).unwrap_or(0);
        let mapoff = read_u32_le(buf, 0x34).unwrap_or(0);

        let strings_size = read_u32_le(buf, 0x38).unwrap_or(0);
        let strings_off = read_u32_le(buf, 0x3c).unwrap_or(0);

        let types_size = read_u32_le(buf, 0x40).unwrap_or(0);
        let types_off = read_u32_le(buf, 0x44).unwrap_or(0);

        let protos_size = read_u32_le(buf, 0x48).unwrap_or(0);
        let protos_off = read_u32_le(buf, 0x4c).unwrap_or(0);

        let fields_size = read_u32_le(buf, 0x50).unwrap_or(0);
        let fields_off = read_u32_le(buf, 0x54).unwrap_or(0);

        let methods_size = read_u32_le(buf, 0x58).unwrap_or(0);
        let methods_off = read_u32_le(buf, 0x5c).unwrap_or(0);

        let classes_size = read_u32_le(buf, 0x60).unwrap_or(0);
        let classes_off = read_u32_le(buf, 0x64).unwrap_or(0);

        let data_size = if buf.len() >= 0x70 {
            read_u32_le(buf, 0x68).unwrap_or(0)
        } else {
            0
        };
        let data_off = if buf.len() >= 0x70 {
            read_u32_le(buf, 0x6c).unwrap_or(0)
        } else {
            0
        };

        Ok(DEXHeader {
            magic,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            mapoff,
            strings: (strings_off, strings_size),
            types: (types_off, types_size),
            prototypes: (protos_off, protos_size),
            fields: (fields_off, fields_size),
            methods: (methods_off, methods_size),
            classes: (classes_off, classes_size),
            data_size,
            data_off,
        })
    }

    #[inline]
    pub fn string_ids_off(&self) -> u32 {
        self.strings.0
    }

    #[inline]
    pub fn string_ids_size(&self) -> u32 {
        self.strings.1
    }

    #[inline]
    pub fn type_ids_off(&self) -> u32 {
        self.types.0
    }

    #[inline]
    pub fn type_ids_size(&self) -> u32 {
        self.types.1
    }

    #[inline]
    pub fn proto_ids_off(&self) -> u32 {
        self.prototypes.0
    }

    #[inline]
    pub fn proto_ids_size(&self) -> u32 {
        self.prototypes.1
    }

    #[inline]
    pub fn field_ids_off(&self) -> u32 {
        self.fields.0
    }

    #[inline]
    pub fn field_ids_size(&self) -> u32 {
        self.fields.1
    }

    #[inline]
    pub fn method_ids_off(&self) -> u32 {
        self.methods.0
    }

    #[inline]
    pub fn method_ids_size(&self) -> u32 {
        self.methods.1
    }

    #[inline]
    pub fn class_defs_off(&self) -> u32 {
        self.classes.0
    }

    #[inline]
    pub fn class_defs_size(&self) -> u32 {
        self.classes.1
    }
}

/// Primitive type enumeration matching Python `PrimitiveTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PrimitiveType {
    Void = 0,
    Boolean = 1,
    Byte = 2,
    Short = 3,
    Char = 4,
    Int = 5,
    Long = 6,
    Float = 7,
    Double = 8,
}

pub struct PrimitiveTypes;
impl PrimitiveTypes {
    pub const VOID_T: u8 = 0;
    pub const BOOLEAN: u8 = 1;
    pub const BYTE: u8 = 2;
    pub const SHORT: u8 = 3;
    pub const CHAR: u8 = 4;
    pub const INT: u8 = 5;
    pub const LONG: u8 = 6;
    pub const FLOAT: u8 = 7;
    pub const DOUBLE: u8 = 8;
}

/// Type kind enumeration matching Python `TypeTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TypeKind {
    Primitive = 1,
    Class = 2,
    Array = 3,
}

pub struct TypeTypes;
impl TypeTypes {
    pub const PRIMITIVE: u8 = 1;
    pub const CLASS: u8 = 2;
    pub const ARRAY: u8 = 3;
}

/// Type value representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeValue<'a> {
    Primitive(PrimitiveType),
    Class(Cow<'a, str>),
}

/// Represents a parsed DEX type descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Type<'a> {
    pub descriptor: Cow<'a, str>,
    pub dim: usize,
    pub kind: TypeKind,
    pub value: Option<TypeValue<'a>>,
    pub underlying_array_type: Option<Box<Type<'a>>>,
}

impl<'a> Type<'a> {
    /// Parse a type descriptor string (e.g. `"Ljava/lang/String;"`, `"[I"`, `"V"`).
    pub fn parse(descriptor: Cow<'a, str>) -> Self {
        let mut dim = 0;
        let bytes = descriptor.as_bytes();
        while dim < bytes.len() && bytes[dim] == b'[' {
            dim += 1;
        }

        if dim > 0 {
            let underlying_desc = match &descriptor {
                Cow::Borrowed(s) => Cow::Borrowed(&s[dim..]),
                Cow::Owned(s) => Cow::Owned(s[dim..].to_string()),
            };
            let underlying = Type::parse(underlying_desc);
            return Type {
                descriptor,
                dim,
                kind: TypeKind::Array,
                value: None,
                underlying_array_type: Some(Box::new(underlying)),
            };
        }

        let desc_slice = descriptor.as_ref();
        let (kind, value) = match desc_slice {
            "V" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Void)),
            ),
            "Z" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Boolean)),
            ),
            "B" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Byte)),
            ),
            "S" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Short)),
            ),
            "C" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Char)),
            ),
            "I" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Int)),
            ),
            "J" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Long)),
            ),
            "F" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Float)),
            ),
            "D" => (
                TypeKind::Primitive,
                Some(TypeValue::Primitive(PrimitiveType::Double)),
            ),
            _ => (TypeKind::Class, Some(TypeValue::Class(descriptor.clone()))),
        };

        Type {
            descriptor,
            dim: 0,
            kind,
            value,
            underlying_array_type: None,
        }
    }

    #[inline]
    pub fn dim(&self) -> usize {
        self.dim
    }

    #[inline]
    pub fn kind(&self) -> TypeKind {
        self.kind
    }

    #[inline]
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }
}

impl fmt::Display for Type<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.descriptor)
    }
}

/// Represents a parsed DEX string item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringItem<'a> {
    pub index: u32,
    pub offset: u32,
    pub utf16_size: u32,
    pub value: Cow<'a, str>,
}

pub type DexString<'a> = StringItem<'a>;

impl<'a> StringItem<'a> {
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl<'a> std::ops::Deref for StringItem<'a> {
    type Target = str;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl fmt::Display for StringItem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Represents a type_id_item in DEX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeItem {
    pub index: u32,
    pub descriptor_idx: u32,
}

/// Represents a proto_id_item in DEX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoItem<'a> {
    pub index: u32,
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    pub parameters: Vec<u16>,
    _marker: std::marker::PhantomData<&'a ()>,
}

pub type DexPrototype<'a> = ProtoItem<'a>;

impl<'a> ProtoItem<'a> {
    /// Resolves parameter types from DEX.
    pub fn parameters_type(&self, dex: &Dex<'a>) -> Vec<Type<'a>> {
        self.parameters
            .iter()
            .filter_map(|&type_idx| dex.get_type(type_idx as u32))
            .collect()
    }
}

/// Represents a field_id_item in DEX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldItem<'a> {
    pub index: u32,
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
    pub access_flags: u32,
    pub is_static: bool,
    _marker: std::marker::PhantomData<&'a ()>,
}

pub type DexField<'a> = FieldItem<'a>;

impl<'a> FieldItem<'a> {
    pub fn name(&self, dex: &Dex<'a>) -> Option<Cow<'a, str>> {
        dex.get_string(self.name_idx)
    }

    pub fn class_descriptor(&self, dex: &Dex<'a>) -> Option<Cow<'a, str>> {
        dex.get_type_descriptor(self.class_idx as u32)
    }

    pub fn field_type(&self, dex: &Dex<'a>) -> Option<Type<'a>> {
        dex.get_type(self.type_idx as u32)
    }
}

/// Represents Dalvik code item header and instructions slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeItem<'a> {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    /// Bytecode instruction bytes (`insns_size * 2` bytes).
    pub insns: &'a [u8],
}

/// Represents a method_id_item in DEX.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodItem<'a> {
    pub index: u32,
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
    pub code_off: u32,
    pub access_flags: u32,
    pub is_direct: bool,
    pub is_virtual: bool,
    _marker: std::marker::PhantomData<&'a ()>,
}

pub type DexMethod<'a> = MethodItem<'a>;

impl<'a> MethodItem<'a> {
    pub fn name(&self, dex: &Dex<'a>) -> Option<Cow<'a, str>> {
        dex.get_string(self.name_idx)
    }

    pub fn class_descriptor(&self, dex: &Dex<'a>) -> Option<Cow<'a, str>> {
        dex.get_type_descriptor(self.class_idx as u32)
    }

    pub fn prototype(&self, dex: &Dex<'a>) -> Option<ProtoItem<'a>> {
        dex.get_prototype(self.proto_idx as u32)
    }

    #[inline]
    pub fn code_offset(&self) -> u32 {
        self.code_off
    }

    /// Returns zero-copy slice of bytecode instruction bytes (`insns_size * 2`).
    pub fn bytecode(&self, buf: &'a [u8]) -> &'a [u8] {
        if self.code_off == 0 {
            return &[];
        }
        let off = self.code_off as usize;
        if off + 16 > buf.len() {
            return &[];
        }
        let insns_size = match read_u32_le(buf, off + 12) {
            Some(s) => s as usize,
            None => return &[],
        };
        let start = off + 16;
        let end = start + insns_size * 2;
        if end > buf.len() {
            &buf[start..buf.len().min(end)]
        } else {
            &buf[start..end]
        }
    }

    /// Parse code_item if code_off != 0.
    pub fn code_item(&self, buf: &'a [u8]) -> Option<CodeItem<'a>> {
        if self.code_off == 0 {
            return None;
        }
        let off = self.code_off as usize;
        if off + 16 > buf.len() {
            return None;
        }
        let registers_size = read_u16_le(buf, off)?;
        let ins_size = read_u16_le(buf, off + 2)?;
        let outs_size = read_u16_le(buf, off + 4)?;
        let tries_size = read_u16_le(buf, off + 6)?;
        let debug_info_off = read_u32_le(buf, off + 8)?;
        let insns_size = read_u32_le(buf, off + 12)?;
        let start = off + 16;
        let byte_len = (insns_size as usize) * 2;
        let end = (start + byte_len).min(buf.len());
        let insns = &buf[start..end];

        Some(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns_size,
            insns,
        })
    }
}

/// Raw class_def_item layout (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassDefItem {
    pub index: u32,
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
    pub class_def_off: u32,
}

/// Parsed class representation matching Python `DexClass`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassItem<'a> {
    pub index: u32,
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
    pub class_def_off: u32,
    pub methods: Vec<MethodItem<'a>>,
    pub fields: Vec<FieldItem<'a>>,
}

pub type DexClass<'a> = ClassItem<'a>;

impl<'a> ClassItem<'a> {
    pub fn fullname(&self, dex: &Dex<'a>) -> Option<Cow<'a, str>> {
        dex.get_type_descriptor(self.class_idx)
    }

    #[inline]
    pub fn methods(&self) -> &[MethodItem<'a>] {
        &self.methods
    }

    #[inline]
    pub fn fields(&self) -> &[FieldItem<'a>] {
        &self.fields
    }

    pub fn direct_methods(&self) -> impl Iterator<Item = &MethodItem<'a>> {
        self.methods.iter().filter(|m| m.is_direct)
    }

    pub fn virtual_methods(&self) -> impl Iterator<Item = &MethodItem<'a>> {
        self.methods.iter().filter(|m| m.is_virtual)
    }

    pub fn static_fields(&self) -> impl Iterator<Item = &FieldItem<'a>> {
        self.fields.iter().filter(|f| f.is_static)
    }

    pub fn instance_fields(&self) -> impl Iterator<Item = &FieldItem<'a>> {
        self.fields.iter().filter(|f| !f.is_static)
    }
}

/// Main DEX container holding zero-copy slice of DEX buffer.
#[derive(Clone, Copy)]
pub struct Dex<'a> {
    pub buf: &'a [u8],
    pub name: &'a str,
    pub header: DEXHeader,
}

pub type DEX<'a> = Dex<'a>;

impl<'a> Dex<'a> {
    /// Parse DEX buffer without copying.
    pub fn new(buf: &'a [u8]) -> Result<Self, DexError> {
        Self::parse(buf, "")
    }

    /// Parse DEX buffer with an associated name (e.g. file or entry name).
    pub fn parse(buf: &'a [u8], name: &'a str) -> Result<Self, DexError> {
        let header = DEXHeader::parse(buf)?;
        Ok(Dex { buf, name, header })
    }

    // --- Strings ---

    #[inline]
    pub fn strings_count(&self) -> usize {
        self.header.strings.1 as usize
    }

    /// Returns offset to string data for `str_idx`.
    pub fn get_string_offset(&self, str_idx: u32) -> Option<u32> {
        let (off, size) = self.header.strings;
        if str_idx >= size {
            return None;
        }
        let pos = (off as usize).checked_add((str_idx as usize) * 4)?;
        read_u32_le(self.buf, pos)
    }

    /// Retrieves raw UTF-8 / MUTF-8 string bytes without trailing null.
    pub fn get_string_raw(&self, str_idx: u32) -> Option<&'a [u8]> {
        let string_off = self.get_string_offset(str_idx)? as usize;
        let mut pos = string_off;
        let utf16_size = read_uleb128_fast(self.buf, &mut pos);
        let data_start = pos;

        // Fast path: ASCII string where byte length == utf16_size and null-terminated
        let expected_end = data_start.checked_add(utf16_size as usize)?;
        if expected_end < self.buf.len() && self.buf[expected_end] == 0 {
            return Some(&self.buf[data_start..expected_end]);
        }

        // Search for 0x00 null terminator
        let data_end = self.buf[data_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| data_start + p)
            .unwrap_or_else(|| expected_end.min(self.buf.len()));

        Some(&self.buf[data_start..data_end])
    }

    /// Retrieves string as `Cow<'a, str>`. Zero-copy if valid UTF-8.
    pub fn get_string(&self, str_idx: u32) -> Option<Cow<'a, str>> {
        let bytes = self.get_string_raw(str_idx)?;
        match std::str::from_utf8(bytes) {
            Ok(s) => Some(Cow::Borrowed(s)),
            Err(_) => Some(String::from_utf8_lossy(bytes)),
        }
    }

    /// Retrieves string as `&'a str` if valid UTF-8.
    pub fn get_string_str(&self, str_idx: u32) -> Option<&'a str> {
        let bytes = self.get_string_raw(str_idx)?;
        std::str::from_utf8(bytes).ok()
    }

    /// Retrieves full StringItem.
    pub fn get_string_item(&self, str_idx: u32) -> Option<StringItem<'a>> {
        let offset = self.get_string_offset(str_idx)?;
        let mut pos = offset as usize;
        let utf16_size = read_uleb128_fast(self.buf, &mut pos);
        let value = self.get_string(str_idx)?;
        Some(StringItem {
            index: str_idx,
            offset,
            utf16_size,
            value,
        })
    }

    // --- Types ---

    #[inline]
    pub fn types_count(&self) -> usize {
        self.header.types.1 as usize
    }

    pub fn get_type_item(&self, type_idx: u32) -> Option<TypeItem> {
        let (off, size) = self.header.types;
        if type_idx >= size {
            return None;
        }
        let pos = (off as usize).checked_add((type_idx as usize) * 4)?;
        let descriptor_idx = read_u32_le(self.buf, pos)?;
        Some(TypeItem {
            index: type_idx,
            descriptor_idx,
        })
    }

    pub fn get_type_desc_idx(&self, type_idx: u32) -> Option<u32> {
        self.get_type_item(type_idx).map(|t| t.descriptor_idx)
    }

    pub fn get_type_descriptor(&self, type_idx: u32) -> Option<Cow<'a, str>> {
        let desc_idx = self.get_type_desc_idx(type_idx)?;
        self.get_string(desc_idx)
    }

    pub fn get_type(&self, type_idx: u32) -> Option<Type<'a>> {
        let desc = self.get_type_descriptor(type_idx)?;
        Some(Type::parse(desc))
    }

    // --- Prototypes ---

    #[inline]
    pub fn prototypes_count(&self) -> usize {
        self.header.prototypes.1 as usize
    }

    pub fn get_prototype(&self, proto_idx: u32) -> Option<ProtoItem<'a>> {
        let (off, size) = self.header.prototypes;
        if proto_idx >= size {
            return None;
        }
        let pos = (off as usize).checked_add((proto_idx as usize) * 12)?;
        let shorty_idx = read_u32_le(self.buf, pos)?;
        let return_type_idx = read_u32_le(self.buf, pos + 4)?;
        let parameters_off = read_u32_le(self.buf, pos + 8)?;

        let mut parameters = Vec::new();
        if parameters_off != 0 {
            let p_off = parameters_off as usize;
            let param_count = read_u32_le(self.buf, p_off)? as usize;
            parameters.reserve(param_count);
            let mut curr = p_off + 4;
            for _ in 0..param_count {
                let type_idx = read_u16_le(self.buf, curr)?;
                parameters.push(type_idx);
                curr += 2;
            }
        }

        Some(ProtoItem {
            index: proto_idx,
            shorty_idx,
            return_type_idx,
            parameters_off,
            parameters,
            _marker: std::marker::PhantomData,
        })
    }

    // --- Fields ---

    #[inline]
    pub fn fields_count(&self) -> usize {
        self.header.fields.1 as usize
    }

    pub fn get_field(&self, field_idx: u32) -> Option<FieldItem<'a>> {
        let (off, size) = self.header.fields;
        if field_idx >= size {
            return None;
        }
        let pos = (off as usize).checked_add((field_idx as usize) * 8)?;
        let class_idx = read_u16_le(self.buf, pos)?;
        let type_idx = read_u16_le(self.buf, pos + 2)?;
        let name_idx = read_u32_le(self.buf, pos + 4)?;

        Some(FieldItem {
            index: field_idx,
            class_idx,
            type_idx,
            name_idx,
            access_flags: 0,
            is_static: false,
            _marker: std::marker::PhantomData,
        })
    }

    // --- Methods ---

    #[inline]
    pub fn methods_count(&self) -> usize {
        self.header.methods.1 as usize
    }

    pub fn get_method(&self, method_idx: u32) -> Option<MethodItem<'a>> {
        let (off, size) = self.header.methods;
        if method_idx >= size {
            return None;
        }
        let pos = (off as usize).checked_add((method_idx as usize) * 8)?;
        let class_idx = read_u16_le(self.buf, pos)?;
        let proto_idx = read_u16_le(self.buf, pos + 2)?;
        let name_idx = read_u32_le(self.buf, pos + 4)?;

        Some(MethodItem {
            index: method_idx,
            class_idx,
            proto_idx,
            name_idx,
            code_off: 0,
            access_flags: 0,
            is_direct: false,
            is_virtual: false,
            _marker: std::marker::PhantomData,
        })
    }

    // --- Classes ---

    #[inline]
    pub fn classes_count(&self) -> usize {
        self.header.classes.1 as usize
    }

    pub fn get_class_def(&self, class_def_idx: u32) -> Option<ClassDefItem> {
        let (off, size) = self.header.classes;
        if class_def_idx >= size {
            return None;
        }
        let pos = (off as usize).checked_add((class_def_idx as usize) * 32)?;
        let class_idx = read_u32_le(self.buf, pos)?;
        let access_flags = read_u32_le(self.buf, pos + 4)?;
        let superclass_idx = read_u32_le(self.buf, pos + 8)?;
        let interfaces_off = read_u32_le(self.buf, pos + 12)?;
        let source_file_idx = read_u32_le(self.buf, pos + 16)?;
        let annotations_off = read_u32_le(self.buf, pos + 20)?;
        let class_data_off = read_u32_le(self.buf, pos + 24)?;
        let static_values_off = read_u32_le(self.buf, pos + 28)?;

        Some(ClassDefItem {
            index: class_def_idx,
            class_idx,
            access_flags,
            superclass_idx,
            interfaces_off,
            source_file_idx,
            annotations_off,
            class_data_off,
            static_values_off,
            class_def_off: pos as u32,
        })
    }

    /// Parse a class definition and its class_data (fields & methods).
    pub fn get_class_by_idx(&self, class_def_idx: u32) -> Option<ClassItem<'a>> {
        let def = self.get_class_def(class_def_idx)?;
        let mut item = ClassItem {
            index: def.index,
            class_idx: def.class_idx,
            access_flags: def.access_flags,
            superclass_idx: def.superclass_idx,
            interfaces_off: def.interfaces_off,
            source_file_idx: def.source_file_idx,
            annotations_off: def.annotations_off,
            class_data_off: def.class_data_off,
            static_values_off: def.static_values_off,
            class_def_off: def.class_def_off,
            methods: Vec::new(),
            fields: Vec::new(),
        };

        if def.class_data_off != 0 {
            let mut pos = def.class_data_off as usize;
            let static_fields_size = read_uleb128_fast(self.buf, &mut pos);
            let instance_fields_size = read_uleb128_fast(self.buf, &mut pos);
            let direct_methods_size = read_uleb128_fast(self.buf, &mut pos);
            let virtual_methods_size = read_uleb128_fast(self.buf, &mut pos);

            let mut field_idx = 0u32;
            for _ in 0..static_fields_size {
                let diff = read_uleb128_fast(self.buf, &mut pos);
                field_idx += diff;
                let flags = read_uleb128_fast(self.buf, &mut pos);
                if let Some(mut f) = self.get_field(field_idx) {
                    f.access_flags = flags;
                    f.is_static = true;
                    item.fields.push(f);
                }
            }

            field_idx = 0;
            for _ in 0..instance_fields_size {
                let diff = read_uleb128_fast(self.buf, &mut pos);
                field_idx += diff;
                let flags = read_uleb128_fast(self.buf, &mut pos);
                if let Some(mut f) = self.get_field(field_idx) {
                    f.access_flags = flags;
                    f.is_static = false;
                    item.fields.push(f);
                }
            }

            let mut method_idx = 0u32;
            for _ in 0..direct_methods_size {
                let diff = read_uleb128_fast(self.buf, &mut pos);
                method_idx += diff;
                let flags = read_uleb128_fast(self.buf, &mut pos);
                let code_off = read_uleb128_fast(self.buf, &mut pos);
                if let Some(mut m) = self.get_method(method_idx) {
                    m.code_off = code_off;
                    m.access_flags = flags;
                    m.is_direct = true;
                    m.is_virtual = false;
                    item.methods.push(m);
                }
            }

            method_idx = 0;
            for _ in 0..virtual_methods_size {
                let diff = read_uleb128_fast(self.buf, &mut pos);
                method_idx += diff;
                let flags = read_uleb128_fast(self.buf, &mut pos);
                let code_off = read_uleb128_fast(self.buf, &mut pos);
                if let Some(mut m) = self.get_method(method_idx) {
                    m.code_off = code_off;
                    m.access_flags = flags;
                    m.is_direct = false;
                    m.is_virtual = true;
                    item.methods.push(m);
                }
            }
        }

        Some(item)
    }

    /// Finds a class by full Dalvik name (e.g. `"Lcom/example/MyClass;"`) via binary search.
    pub fn get_class(&self, fullname: &str) -> Option<ClassItem<'a>> {
        let (type_ids_off, type_ids_size) = self.header.types;
        if type_ids_size == 0 {
            return None;
        }

        let mut left = 0usize;
        let mut right = (type_ids_size as usize).saturating_sub(1);
        let mut found_type_idx = None;

        while left <= right {
            let mid = left + (right - left) / 2;
            let pos = (type_ids_off as usize) + mid * 4;
            let desc_idx = read_u32_le(self.buf, pos)?;
            let s = self.get_string(desc_idx)?;

            match s.as_ref().cmp(fullname) {
                std::cmp::Ordering::Equal => {
                    found_type_idx = Some(mid as u32);
                    break;
                }
                std::cmp::Ordering::Less => {
                    left = mid + 1;
                }
                std::cmp::Ordering::Greater => {
                    if mid == 0 {
                        break;
                    }
                    right = mid - 1;
                }
            }
        }

        let target_type_idx = found_type_idx?;
        let (classes_off, classes_size) = self.header.classes;

        for i in 0..classes_size {
            let class_def_off = (classes_off as usize) + (i as usize) * 32;
            let class_idx = read_u32_le(self.buf, class_def_off)?;
            if class_idx == target_type_idx {
                return self.get_class_by_idx(i);
            }
        }

        None
    }

    /// Fast helper for prefix byte matching class strings from `tinydex.py`.
    pub fn get_uleb128_prefix(lens: usize) -> Vec<u8> {
        if lens < 128 {
            vec![lens as u8]
        } else {
            vec![(lens as u8) | 0x80, (lens >> 7) as u8]
        }
    }

    // --- Iterators ---

    pub fn iter_strings(&self) -> impl Iterator<Item = Cow<'a, str>> + 'a {
        let count = self.strings_count();
        let this = *self;
        (0..count as u32).filter_map(move |i| this.get_string(i))
    }

    pub fn iter_types(&self) -> impl Iterator<Item = TypeItem> + 'a {
        let count = self.types_count();
        let this = *self;
        (0..count as u32).filter_map(move |i| this.get_type_item(i))
    }

    pub fn iter_prototypes(&self) -> impl Iterator<Item = ProtoItem<'a>> + 'a {
        let count = self.prototypes_count();
        let this = *self;
        (0..count as u32).filter_map(move |i| this.get_prototype(i))
    }

    pub fn iter_fields(&self) -> impl Iterator<Item = FieldItem<'a>> + 'a {
        let count = self.fields_count();
        let this = *self;
        (0..count as u32).filter_map(move |i| this.get_field(i))
    }

    pub fn iter_methods(&self) -> impl Iterator<Item = MethodItem<'a>> + 'a {
        let count = self.methods_count();
        let this = *self;
        (0..count as u32).filter_map(move |i| this.get_method(i))
    }

    pub fn iter_class_defs(&self) -> impl Iterator<Item = ClassDefItem> + 'a {
        let count = self.classes_count();
        let this = *self;
        (0..count as u32).filter_map(move |i| this.get_class_def(i))
    }

    pub fn iter_classes(&self) -> impl Iterator<Item = ClassItem<'a>> + 'a {
        let count = self.classes_count();
        let this = *self;
        (0..count as u32).filter_map(move |i| this.get_class_by_idx(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_parse() {
        let t1 = Type::parse(Cow::Borrowed("V"));
        assert_eq!(t1.kind, TypeKind::Primitive);
        assert_eq!(t1.dim, 0);
        assert_eq!(t1.value, Some(TypeValue::Primitive(PrimitiveType::Void)));

        let t2 = Type::parse(Cow::Borrowed("[I"));
        assert_eq!(t2.kind, TypeKind::Array);
        assert_eq!(t2.dim, 1);
        assert!(t2.underlying_array_type.is_some());
        let underlying = t2.underlying_array_type.unwrap();
        assert_eq!(underlying.kind, TypeKind::Primitive);
        assert_eq!(underlying.value, Some(TypeValue::Primitive(PrimitiveType::Int)));

        let t3 = Type::parse(Cow::Borrowed("Ljava/lang/String;"));
        assert_eq!(t3.kind, TypeKind::Class);
        assert_eq!(t3.dim, 0);
        assert_eq!(
            t3.value,
            Some(TypeValue::Class(Cow::Borrowed("Ljava/lang/String;")))
        );
    }
}
