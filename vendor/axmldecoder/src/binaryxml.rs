//! Validating binary-XML reader producing the ordered document model
//! (AX-P02/AX-P03/AX-P04).
//!
//! The whole declared document length is walked with a bounds-checked cursor.
//! Structural invariants enforced here: a document chunk whose size matches the
//! input exactly; a string pool followed by at most one resource map; only the
//! five XML node chunk types; start/end element and start/end namespace pairs
//! matched by their raw indices; exactly one root element; duplicate
//! attributes rejected; string indices validated; depth/node/attribute
//! budgets; and full consumption of the node stream (a second root or trailing
//! structural garbage is an error, never a silent early success).

use crate::cursor::Cursor;
use crate::stringpool::{read_string_pool, StringPoolData, NO_INDEX};
use crate::xml::attribute_name_for_resource;
use crate::{DecodeLimits, ParseError};

// Chunk types (ResChunk_header::type).
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;

/// The smallest chunk that carries a node header (chunk header + line + comment).
const NODE_HEADER_SIZE: usize = 16;
/// Size of the fixed part of a start-element ext header plus the chunk header.
const ELEMENT_EXT_SIZE: usize = 20;
/// Size of one attribute slot as aapt writes it.
const ATTRIBUTE_SIZE: usize = 20;

/// One typed value, kept raw: the `type` byte and `data` word exactly as the
/// document stores them (AX-P03). Projection to readable text is not done in
/// this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawValue {
    pub type_byte: u8,
    pub data: u32,
}

/// One namespace start/end as it appeared in the node stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamespaceEvent {
    Start { prefix: String, uri: String },
    End { prefix: String, uri: String },
}

/// One attribute: resolved namespace URI, final name, optional raw string and
/// the typed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    pub namespace: Option<String>,
    pub name: String,
    pub raw_value: Option<String>,
    pub value: RawValue,
}

/// A CDATA node; binary XML represents text as CDATA chunks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cdata {
    pub data: String,
    pub value: RawValue,
    pub line_number: u32,
    pub comment: Option<String>,
}

/// One element with its ordered children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    /// Opening order of the element (pre-order sequence), used to correlate
    /// namespace events recorded on the document.
    pub seq: u32,
    pub line_number: u32,
    pub comment: Option<String>,
    pub namespace: Option<String>,
    pub name: String,
    /// Namespace events whose start chunk carried this element's sequence as
    /// the innermost open element, in stream order.
    pub namespace_events: Vec<NamespaceEvent>,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Node>,
}

/// A node inside an element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Element(Element),
    Cdata(Cdata),
}

/// The parsed document: string-pool data, resource map, the single root and
/// the namespace events that occurred after the root closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    pub string_pool: StringPoolData,
    pub resource_map: Vec<u32>,
    pub root: Element,
    /// Namespace events after the root element closed; normally the end
    /// events matching the root's bindings.
    pub epilog_namespaces: Vec<NamespaceEvent>,
}

/// One open element while the stream is being folded into a tree.
struct OpenElement {
    seq: u32,
    ns_index: u32,
    name_index: u32,
    element: Element,
}

/// One open namespace binding: the raw prefix/uri indices (for exact end
/// matching) and the element the binding's start event attached to.
struct OpenNamespace {
    prefix_index: u32,
    uri_index: u32,
    /// `None` for pending starts that have not seen their element yet.
    owner_seq: Option<u32>,
}

pub(crate) fn parse(data: &[u8], limits: &DecodeLimits) -> Result<Document, ParseError> {
    if limits.max_depth == 0 || limits.max_nodes == 0 || limits.max_attributes == 0
        || limits.max_string_units == 0
    {
        return Err(ParseError::Limit(
            "decode limits must be positive".to_owned(),
        ));
    }

    let mut cursor = Cursor::new(data);
    let doc_type = cursor.u16()?;
    let header_size = cursor.u16()?;
    let doc_size = cursor.u32()? as usize;
    if doc_type != RES_XML_TYPE {
        return Err(ParseError::Malformed(format!(
            "input does not start with a binary XML document chunk (0x0003), found 0x{doc_type:04X}"
        )));
    }
    if usize::from(header_size) < 8 {
        return Err(ParseError::Malformed(format!(
            "document chunk header size {header_size} cannot hold its own fields"
        )));
    }
    // AX-P02: the declared length must cover exactly the input, so nothing
    // outside the chunk can be smuggled in and nothing declared is left
    // unread. A header larger than the conventional 8 bytes is an unknown
    // layout; the structure remains readable, so parsing continues from it.
    if doc_size != data.len() {
        return Err(ParseError::Malformed(format!(
            "document chunk declares {doc_size} bytes but the input is {} bytes",
            data.len()
        )));
    }
    let end = doc_size;
    let mut pos = usize::from(header_size);

    let (string_pool, pool_size) = read_string_pool(data, pos, limits.max_string_units)?;
    pos += pool_size;

    let mut resource_map = Vec::new();
    if pos.checked_add(8).is_some_and(|p| p <= end) {
        let map_type = u16_at(data, pos)?;
        if map_type == RES_XML_RESOURCE_MAP_TYPE {
            let map_header_size = u16_at(data, pos + 2)?;
            let map_size = u32_at(data, pos + 4)? as usize;
            let header = usize::from(map_header_size);
            if header < 8 || map_size < header || (map_size - header) % 4 != 0 {
                return Err(ParseError::Malformed(format!(
                    "resource map chunk at {pos} is malformed: header_size={map_header_size}, size={map_size}"
                )));
            }
            if pos + map_size > end {
                return Err(ParseError::Malformed(format!(
                    "resource map chunk at {pos} runs past the document end {end}"
                )));
            }
            let count = (map_size - header) / 4;
            let mut map_cursor = Cursor::new(data);
            map_cursor.seek(pos + header)?;
            for _ in 0..count {
                resource_map.push(map_cursor.u32()?);
            }
            pos += map_size;
        }
    }

    parse_node_stream(
        data,
        pos,
        end,
        &string_pool,
        &resource_map,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_node_stream(
    data: &[u8],
    mut pos: usize,
    end: usize,
    string_pool: &StringPoolData,
    resource_map: &[u32],
    limits: &DecodeLimits,
) -> Result<Document, ParseError> {
    let mut stack: Vec<OpenElement> = Vec::new();
    let mut ns_stack: Vec<OpenNamespace> = Vec::new();
    // Namespace starts that have not yet seen the element they bind for.
    let mut pending_ns: Vec<(u32, u32)> = Vec::new();
    let mut root: Option<Element> = None;
    let mut epilog: Vec<NamespaceEvent> = Vec::new();
    let mut seq: u32 = 0;
    let mut node_count: usize = 0;
    let mut attribute_count: usize = 0;

    while pos < end {
        let chunk_type = u16_at(data, pos)?;
        let header_size = u16_at(data, pos + 2)?;
        let chunk_size = u32_at(data, pos + 4)? as usize;
        let header = usize::from(header_size);
        if header < NODE_HEADER_SIZE || chunk_size < header {
            return Err(ParseError::Malformed(format!(
                "node chunk at {pos} is malformed: header_size={header_size}, size={chunk_size}"
            )));
        }
        if pos.checked_add(chunk_size).is_none_or(|p| p > end) {
            return Err(ParseError::Malformed(format!(
                "node chunk at {pos} runs past the document end {end}"
            )));
        }
        let line_number = u32_at(data, pos + 8)?;
        let comment_index = u32_at(data, pos + 12)?;
        let payload_start = pos + header;
        let payload_end = pos + chunk_size;

        match chunk_type {
            RES_XML_START_NAMESPACE_TYPE => {
                require_payload(payload_start, payload_end, 8, "namespace start")?;
                let prefix_index = u32_at(data, payload_start)?;
                let uri_index = u32_at(data, payload_start + 4)?;
                // Resolve now so index validation happens even before the
                // binding attaches to an element.
                string_pool.require(prefix_index, "namespace prefix")?;
                string_pool.require(uri_index, "namespace uri")?;
                ns_stack.push(OpenNamespace { prefix_index, uri_index, owner_seq: None });
                pending_ns.push((prefix_index, uri_index));
            }
            RES_XML_END_NAMESPACE_TYPE => {
                require_payload(payload_start, payload_end, 8, "namespace end")?;
                let prefix_index = u32_at(data, payload_start)?;
                let uri_index = u32_at(data, payload_start + 4)?;
                // AX-P02: an end namespace must match the innermost open start.
                if !ns_stack.last().is_some_and(|open| {
                    open.prefix_index == prefix_index && open.uri_index == uri_index
                }) {
                    return Err(ParseError::Malformed(format!(
                        "end namespace at {pos} (prefix index {prefix_index}, uri index \
                         {uri_index}) does not match the innermost open start namespace"
                    )));
                }
                let Some(closed) = ns_stack.pop() else {
                    return Err(ParseError::Malformed(
                        "end namespace without a matching start namespace".to_owned(),
                    ));
                };
                let prefix = string_pool.require(closed.prefix_index, "namespace prefix")?;
                let uri = string_pool.require(closed.uri_index, "namespace uri")?;
                match closed.owner_seq {
                    // The binding's element may still be open: record the end
                    // on it so scopes reconstruct exactly.
                    Some(owner) => {
                        let event = NamespaceEvent::End { prefix, uri };
                        if !attach_event(&mut stack, owner, event.clone())?
                            && stack.is_empty()
                            && root.is_some()
                        {
                            // The owner (necessarily the root here) already
                            // closed: the end belongs to the epilog.
                            epilog.push(event);
                        }
                    }
                    None => {
                        // Pending start (no element followed) or a start owned
                        // by the root that already closed: both live at
                        // document level.
                        pending_ns.retain(|&(p, _)| p != closed.prefix_index);
                        if root.is_some() {
                            epilog.push(NamespaceEvent::End { prefix, uri });
                        }
                    }
                }
            }
            RES_XML_START_ELEMENT_TYPE => {
                seq = seq
                    .checked_add(1)
                    .ok_or_else(|| ParseError::Malformed("element count overflows".to_owned()))?;
                node_count += 1;
                if node_count > limits.max_nodes {
                    return Err(ParseError::Limit(format!(
                        "document exceeds the node limit of {}",
                        limits.max_nodes
                    )));
                }
                let element = parse_element(
                    data,
                    pos,
                    payload_start,
                    payload_end,
                    line_number,
                    comment_index,
                    seq,
                    string_pool,
                    resource_map,
                    limits,
                    &mut attribute_count,
                )?;
                // Namespace starts waiting for this element attach to it.
                let mut element = element;
                for &(prefix_index, uri_index) in &pending_ns {
                    let prefix = string_pool.require(prefix_index, "namespace prefix")?;
                    let uri = string_pool.require(uri_index, "namespace uri")?;
                    element.namespace_events.push(NamespaceEvent::Start { prefix, uri });
                    if let Some(open) = ns_stack.iter_mut().rev().find(|open| {
                        open.prefix_index == prefix_index && open.uri_index == uri_index
                            && open.owner_seq.is_none()
                    }) {
                        open.owner_seq = Some(seq);
                    }
                }
                pending_ns.clear();

                if stack.len() + 1 > limits.max_depth {
                    return Err(ParseError::Limit(format!(
                        "document nesting exceeds the depth limit of {}",
                        limits.max_depth
                    )));
                }
                let ns_index = u32_at(data, payload_start)?;
                let name_index = u32_at(data, payload_start + 4)?;
                if stack.is_empty() && root.is_some() {
                    return Err(ParseError::Malformed(
                        "document has a second root element".to_owned(),
                    ));
                }
                stack.push(OpenElement { seq, ns_index, name_index, element });
            }
            RES_XML_END_ELEMENT_TYPE => {
                require_payload(payload_start, payload_end, 8, "element end")?;
                let ns_index = u32_at(data, payload_start)?;
                let name_index = u32_at(data, payload_start + 4)?;
                let open = stack.pop().ok_or_else(|| {
                    ParseError::Malformed("end element without a matching start element".to_owned())
                })?;
                // AX-P02: the end chunk must carry the same indices as the start.
                if open.ns_index != ns_index || open.name_index != name_index {
                    return Err(ParseError::Malformed(format!(
                        "end element at {pos} (ns {ns_index}, name {name_index}) does not \
                         match the open start element (ns {}, name {})",
                        open.ns_index, open.name_index
                    )));
                }
                let finished = open.element;
                match stack.last_mut() {
                    Some(parent) => parent.element.children.push(Node::Element(finished)),
                    None => {
                        root = Some(finished);
                    }
                }
            }
            RES_XML_CDATA_TYPE => {
                require_payload(payload_start, payload_end, 12, "cdata")?;
                node_count += 1;
                if node_count > limits.max_nodes {
                    return Err(ParseError::Limit(format!(
                        "document exceeds the node limit of {}",
                        limits.max_nodes
                    )));
                }
                let data_index = u32_at(data, payload_start)?;
                let value = read_raw_value(data, payload_start + 4)?;
                let text = string_pool.require(data_index, "cdata data")?;
                let comment = resolve_comment(string_pool, comment_index)?;
                let node = Node::Cdata(Cdata { data: text, value, line_number, comment });
                match stack.last_mut() {
                    Some(parent) => parent.element.children.push(node),
                    // AX-P02: text outside any element is a structural error.
                    None => {
                        return Err(ParseError::Malformed(
                            "character data outside any element".to_owned(),
                        ))
                    }
                }
            }
            other => {
                return Err(ParseError::Malformed(format!(
                    "unknown node chunk type 0x{other:04X} at {pos}"
                )));
            }
        }
        pos += chunk_size;
    }

    if pos != end {
        return Err(ParseError::Malformed(format!(
            "node stream ended at {pos} before the document end {end}"
        )));
    }
    if !pending_ns.is_empty() {
        return Err(ParseError::Malformed(
            "namespace start without a following element".to_owned(),
        ));
    }
    if !ns_stack.is_empty() {
        return Err(ParseError::Malformed(
            "unclosed namespace at the end of the document".to_owned(),
        ));
    }
    if !stack.is_empty() {
        return Err(ParseError::Malformed(
            "unclosed element at the end of the document".to_owned(),
        ));
    }
    let root = root.ok_or_else(|| {
        ParseError::Malformed("binary XML document has no root element".to_owned())
    })?;
    Ok(Document { string_pool: string_pool.clone(), resource_map: resource_map.to_vec(), root, epilog_namespaces: epilog })
}

#[allow(clippy::too_many_arguments)]
fn parse_element(
    data: &[u8],
    chunk_start: usize,
    payload_start: usize,
    payload_end: usize,
    line_number: u32,
    comment_index: u32,
    seq: u32,
    string_pool: &StringPoolData,
    resource_map: &[u32],
    limits: &DecodeLimits,
    attribute_count: &mut usize,
) -> Result<Element, ParseError> {
    // The 20-byte ext header: ns, name, attributeStart, attributeSize,
    // attributeCount, idIndex, classIndex, styleIndex.
    require_payload(payload_start, payload_end, ELEMENT_EXT_SIZE, "start element")?;
    let ns_index = u32_at(data, payload_start)?;
    let name_index = u32_at(data, payload_start + 4)?;
    let attribute_start = u16_at(data, payload_start + 8)? as usize;
    let attribute_size = u16_at(data, payload_start + 10)? as usize;
    let attribute_count_here = u16_at(data, payload_start + 12)?;
    let id_index = u16_at(data, payload_start + 14)?;
    let class_index = u16_at(data, payload_start + 16)?;
    let style_index = u16_at(data, payload_start + 18)?;

    if attribute_start < ELEMENT_EXT_SIZE || attribute_size < ATTRIBUTE_SIZE {
        return Err(ParseError::Malformed(format!(
            "start element at {chunk_start} declares attributeStart={attribute_start}, \
             attributeSize={attribute_size}"
        )));
    }
    let count = usize::from(attribute_count_here);
    for index in [id_index, class_index, style_index] {
        if index != 0 && usize::from(index) > count {
            return Err(ParseError::Malformed(format!(
                "start element at {chunk_start} declares index {index} beyond its \
                 {attribute_count_here} attributes"
            )));
        }
    }
    let attributes_base = payload_start
        .checked_add(attribute_start)
        .ok_or_else(|| ParseError::Malformed("attribute offset overflow".to_owned()))?;
    let attributes_end = count
        .checked_mul(attribute_size)
        .and_then(|span| attributes_base.checked_add(span))
        .ok_or_else(|| ParseError::Malformed("attribute array overflow".to_owned()))?;
    if attributes_end > payload_end {
        return Err(ParseError::Malformed(format!(
            "start element at {chunk_start} declares {count} attributes of \
             {attribute_size} bytes, past the chunk end {payload_end}"
        )));
    }
    if attribute_count.checked_add(count).is_some_and(|total| total > limits.max_attributes) {
        return Err(ParseError::Limit(format!(
            "document exceeds the cumulative attribute limit of {}",
            limits.max_attributes
        )));
    }

    let namespace = match ns_index {
        NO_INDEX => None,
        index => {
            let uri = string_pool.require(index, "element namespace")?;
            empty_to_none(uri)
        }
    };
    let name = string_pool.require(name_index, "element name")?;
    if name.is_empty() {
        return Err(ParseError::Malformed(format!(
            "start element at {chunk_start} has an empty name"
        )));
    }
    let comment = resolve_comment(string_pool, comment_index)?;

    let mut attributes = Vec::with_capacity(count);
    let mut seen: Vec<(u32, String)> = Vec::with_capacity(count);
    for i in 0..count {
        let at = attributes_base + i * attribute_size;
        let attr_ns_index = u32_at(data, at)?;
        let attr_name_index = u32_at(data, at + 4)?;
        let raw_value_index = u32_at(data, at + 8)?;
        let value = read_raw_value(data, at + 12)?;

        let attr_namespace = match attr_ns_index {
            NO_INDEX => None,
            index => {
                let uri = string_pool.require(index, "attribute namespace")?;
                empty_to_none(uri)
            }
        };
        // An empty attribute name is resolved through the resource map: the
        // name string's index doubles as the map index.
        let attr_name = {
            let raw = string_pool.require(attr_name_index, "attribute name")?;
            if raw.is_empty() {
                let resource_id = *resource_map.get(attr_name_index as usize).ok_or_else(
                    || {
                        ParseError::Malformed(format!(
                            "attribute name index {attr_name_index} is empty and outside the \
                             resource map ({} entries)",
                            resource_map.len()
                        ))
                    },
                )?;
                attribute_name_for_resource(resource_id)
                    .ok_or_else(|| {
                        ParseError::Malformed(format!(
                            "attribute resource id 0x{resource_id:08X} has no known name"
                        ))
                    })?
                    .to_owned()
            } else {
                raw
            }
        };
        // AX-P02: duplicate attributes (same namespace and name) are malformed.
        if seen.iter().any(|(ns, name)| *ns == attr_ns_index && *name == attr_name) {
            return Err(ParseError::Malformed(format!(
                "duplicate attribute {attr_name} on element {name} at {chunk_start}"
            )));
        }
        seen.push((attr_ns_index, attr_name.clone()));

        let raw_value = match raw_value_index {
            NO_INDEX => None,
            index => Some(string_pool.require(index, "attribute raw value")?),
        };
        attributes.push(Attribute { namespace: attr_namespace, name: attr_name, raw_value, value });
    }
    *attribute_count += count;

    Ok(Element {
        seq,
        line_number,
        comment,
        namespace,
        name,
        namespace_events: Vec::new(),
        attributes,
        children: Vec::new(),
    })
}

fn read_raw_value(data: &[u8], at: usize) -> Result<RawValue, ParseError> {
    let size = u16_at(data, at)?;
    let res0 = u8_at(data, at + 2)?;
    let type_byte = u8_at(data, at + 3)?;
    let value_data = u32_at(data, at + 4)?;
    if size != 8 {
        return Err(ParseError::Malformed(format!(
            "typed value at {at} declares size {size}, expected 8"
        )));
    }
    if res0 != 0 {
        return Err(ParseError::Malformed(format!(
            "typed value at {at} has non-zero res0 {res0}"
        )));
    }
    Ok(RawValue { type_byte, data: value_data })
}

fn resolve_comment(
    string_pool: &StringPoolData,
    comment_index: u32,
) -> Result<Option<String>, ParseError> {
    match comment_index {
        NO_INDEX => Ok(None),
        index => Ok(Some(string_pool.require(index, "comment")?)),
    }
}

/// Attaches `event` to the still-open element with sequence `owner_seq`.
/// Returns whether an open element consumed it.
fn attach_event(
    stack: &mut [OpenElement],
    owner_seq: u32,
    event: NamespaceEvent,
) -> Result<bool, ParseError> {
    for open in stack.iter_mut() {
        if open.seq == owner_seq {
            open.element.namespace_events.push(event);
            return Ok(true);
        }
    }
    // The owner already closed: the binding covered its whole subtree, which
    // the scope reconstruction derives without the end event.
    Ok(false)
}

fn empty_to_none(text: String) -> Option<String> {
    if text.is_empty() { None } else { Some(text) }
}

fn require_payload(
    start: usize,
    end: usize,
    size: usize,
    what: &str,
) -> Result<(), ParseError> {
    if start.checked_add(size).is_none_or(|e| e > end) {
        return Err(ParseError::Malformed(format!(
            "{what} chunk payload is smaller than {size} bytes"
        )));
    }
    Ok(())
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, ParseError> {
    let bytes = data
        .get(at..at + 2)
        .ok_or_else(|| ParseError::Malformed(format!("truncated read (u16) at {at}")))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, ParseError> {
    let bytes = data
        .get(at..at + 4)
        .ok_or_else(|| ParseError::Malformed(format!("truncated read (u32) at {at}")))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn u8_at(data: &[u8], at: usize) -> Result<u8, ParseError> {
    data.get(at)
        .copied()
        .ok_or_else(|| ParseError::Malformed(format!("truncated read (u8) at {at}")))
}
