//! Minimal JSON reader for the fixture manifest and expected facts files.
//!
//! The crate ships without serde_json on purpose, and the contract harness only
//! needs to read (never write) JSON, so this is a small recursive-descent
//! parser. Numbers keep their integer/float split because the facts comparator
//! must treat `1` and `1.0` as different values.

/// Parsed JSON value. Objects preserve document order; duplicate keys are
/// rejected by the parser so every key is unambiguous.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        let Json::Object(pairs) = self else {
            return None;
        };
        pairs.iter().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Json> {
        let Json::Object(pairs) = self else {
            return None;
        };
        pairs.iter_mut().find(|(name, _)| name == key).map(|(_, value)| value)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Json>> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            Json::Null => "null",
            Json::Bool(_) => "boolean",
            Json::Int(_) => "integer",
            Json::Float(_) => "float",
            Json::Str(_) => "string",
            Json::Array(_) => "array",
            Json::Object(_) => "object",
        }
    }
}

/// Maximum nesting depth; guards the recursive parser against stack overflow
/// on adversarial files. Authored fixture facts stay far below it.
const MAX_DEPTH: usize = 96;

pub fn parse(text: &str) -> Result<Json, String> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing data at byte {}", parser.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", byte as char, self.pos))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH}"));
        }
        match self.peek().ok_or("unexpected end of input")? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Json::Str(self.string()?)),
            b't' => self.literal("true", Json::Bool(true)),
            b'f' => self.literal("false", Json::Bool(false)),
            b'n' => self.literal("null", Json::Null),
            b'-' | b'0'..=b'9' => self.number(),
            other => Err(format!("unexpected byte {other:#x} at {}", self.pos)),
        }
    }

    fn literal(&mut self, text: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut pairs = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(pairs));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            if pairs.iter().any(|(name, _)| *name == key) {
                return Err(format!("duplicate object key {key:?}"));
            }
            pairs.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(pairs));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = self.peek().ok_or("unterminated string")?;
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let escape = self.peek().ok_or("unterminated escape")?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => return Err(format!("invalid escape \\{}", other as char)),
                    }
                }
                0x00..=0x1f => return Err("control character in string".into()),
                _ => {
                    let len = utf8_sequence_len(byte)?;
                    let end = self.pos + len;
                    let slice = self
                        .bytes
                        .get(self.pos..end)
                        .ok_or("truncated UTF-8 sequence")?;
                    let text = std::str::from_utf8(slice).map_err(|_| "invalid UTF-8 in string")?;
                    out.push_str(text);
                    self.pos = end;
                }
            }
        }
    }

    /// One `\uXXXX` unit; surrogate pairs combine, lone surrogates are
    /// rejected because authored facts must stay valid Unicode.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        let unit = match char::from_u32(u32::from(first)) {
            Some(character) => return Ok(character),
            None => first,
        };
        if !(0xd800..=0xdbff).contains(&unit) {
            return Err("invalid \\u escape".into());
        }
        if self.peek() != Some(b'\\') {
            return Err("lone surrogate in \\u escape".into());
        }
        self.pos += 1;
        self.expect(b'u')?;
        let second = self.hex4()?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return Err("invalid low surrogate in \\u escape".into());
        }
        let combined = 0x10000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
        char::from_u32(combined).ok_or_else(|| "invalid surrogate pair".into())
    }

    fn hex4(&mut self) -> Result<u16, String> {
        let mut value = 0u16;
        for _ in 0..4 {
            let byte = self.peek().ok_or("truncated \\u escape")?;
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a' + 10),
                b'A'..=b'F' => u16::from(byte - b'A' + 10),
                _ => return Err("non-hex digit in \\u escape".into()),
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let mut is_float = false;
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' => self.pos += 1,
                b'.' if !is_float => {
                    is_float = true;
                    self.pos += 1;
                }
                b'e' | b'E' => {
                    is_float = true;
                    self.pos += 1;
                    if matches!(self.peek(), Some(b'+' | b'-')) {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        if is_float {
            Ok(Json::Float(text.parse::<f64>().map_err(|_| format!("invalid float {text}"))?))
        } else {
            Ok(Json::Int(text.parse::<i64>().map_err(|_| format!("invalid integer {text}"))?))
        }
    }
}

fn utf8_sequence_len(lead: u8) -> Result<usize, String> {
    match lead {
        0x00..=0x7f => Ok(1),
        0xc0..=0xdf => Ok(2),
        0xe0..=0xef => Ok(3),
        0xf0..=0xf7 => Ok(4),
        _ => Err("invalid UTF-8 lead byte".into()),
    }
}
