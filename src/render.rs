//! The frozen CLI output protocol (interfaces.md §6): deterministic text
//! lines, bounded JSON envelopes, one serialization shared by `-o` and
//! stdout.
//!
//! Every serialization runs under the `result-bytes` budget: growth past the
//! budget is refused (`ResourceLimit`) before it happens, and the control
//! token is checked at least every 64 KiB of output. Nothing buffers the
//! payload unbounded and checks afterwards.

use crate::error::Error;
use crate::manifest::{Manifest, OperationControl, XmlRenderOptions};
use crate::model::dto::{self, Writer};
use crate::model::{ArtifactId, Class, Diagnostic, Reference, Source, TargetMatch};

/// The text-mode column separator; column content escapes every literal `|`.
const SEP: &str = " | ";
/// Control checkpoints happen at least every 64 KiB of serialized growth.
const CHECK_INTERVAL: usize = 64 * 1024;

/// The per-command payload behind text/json rendering.
pub(crate) enum CommandData<'a> {
    Findrefs(&'a [Reference]),
    Classes(&'a [Class]),
    Getclass(&'a Source),
    Manifest(&'a Manifest),
}

/// Renders the payload in text mode. Empty sets produce empty bytes.
pub(crate) fn text(
    data: &CommandData<'_>,
    budget: usize,
    control: &OperationControl,
) -> Result<String, Error> {
    match data {
        CommandData::Findrefs(rows) => findrefs_text(rows, budget, control),
        CommandData::Classes(rows) => classes_text(rows, budget, control),
        CommandData::Getclass(source) => copy_bounded(source.text(), budget, control),
        CommandData::Manifest(manifest) => manifest
            .to_xml(
                &XmlRenderOptions { max_output_bytes: budget, ..XmlRenderOptions::default() },
                control,
            ),
    }
}

/// Renders the payload as one JSON envelope object plus a single trailing LF.
pub(crate) fn json(
    operation: &str,
    artifact_id: &ArtifactId,
    diagnostics: &[Diagnostic],
    data: &CommandData<'_>,
    budget: usize,
    control: &OperationControl,
) -> Result<String, Error> {
    let rendered = dto::write_envelope_result(operation, artifact_id, diagnostics, |w| {
        w.set_budget(budget);
        let mut checkpoints = Checkpoints::new(budget, control);
        match data {
            CommandData::Findrefs(rows) => {
                w.begin_array();
                for row in *rows {
                    dto::write_reference(w, row);
                    checkpoints.check(w)?;
                }
                w.end_array();
            }
            CommandData::Classes(rows) => {
                w.begin_array();
                for row in *rows {
                    dto::write_class(w, row);
                    checkpoints.check(w)?;
                }
                w.end_array();
            }
            CommandData::Getclass(source) => {
                control.check()?;
                w.begin_object();
                w.key("class");
                dto::write_class(w, source.class());
                w.key("source");
                w.string(source.text());
                w.key("metadata");
                dto::write_source_metadata(w, source.metadata());
                w.end_object();
                control.check()?;
            }
            CommandData::Manifest(manifest) => {
                control.check()?;
                // The XML is complete or the command fails; never a null xml.
                let xml = manifest.to_xml(
                    &XmlRenderOptions { max_output_bytes: budget, ..XmlRenderOptions::default() },
                    control,
                )?;
                w.begin_object();
                w.key("xml");
                w.string(&xml);
                w.key("document");
                crate::manifest::write_document_dto(w, manifest);
                w.end_object();
                control.check()?;
            }
        }
        checkpoints.check(w)?;
        Ok(())
    })?;
    let mut payload = rendered;
    payload.push('\n');
    Ok(payload)
}

/// Budget and control checkpoints shared by the JSON rendering paths.
struct Checkpoints<'a> {
    budget: usize,
    since_check: usize,
    control: &'a OperationControl,
}

impl<'a> Checkpoints<'a> {
    fn new(budget: usize, control: &'a OperationControl) -> Self {
        Self { budget, since_check: 0, control }
    }

    fn check(&mut self, writer: &Writer) -> Result<(), Error> {
        if writer.over_budget() {
            return Err(self.limit_error());
        }
        if writer.len() - self.since_check >= CHECK_INTERVAL {
            self.control.check()?;
            self.since_check = writer.len();
        }
        Ok(())
    }

    fn limit_error(&self) -> Error {
        Error::resource_limit(format!(
            "serialized payload exceeds the {} byte result-bytes limit",
            self.budget
        ))
    }
}

/// Bounded text accumulator: refuses growth past the budget and checks the
/// control token at the 64 KiB cadence.
struct TextOut<'a> {
    out: String,
    budget: usize,
    since_check: usize,
    control: &'a OperationControl,
}

impl<'a> TextOut<'a> {
    fn new(budget: usize, control: &'a OperationControl) -> Self {
        Self { out: String::new(), budget, since_check: 0, control }
    }

    fn push(&mut self, text: &str) -> Result<(), Error> {
        if self.out.len() + text.len() > self.budget {
            return Err(Error::resource_limit(format!(
                "serialized payload exceeds the {} byte result-bytes limit",
                self.budget
            )));
        }
        self.out.push_str(text);
        if self.out.len() - self.since_check >= CHECK_INTERVAL {
            self.control.check()?;
            self.since_check = self.out.len();
        }
        Ok(())
    }
}

/// Copies an already materialized payload (the decompiled source) under the
/// same budget and checkpoint rules.
fn copy_bounded(text: &str, budget: usize, control: &OperationControl) -> Result<String, Error> {
    let mut out = TextOut::new(budget, control);
    control.check()?;
    let mut rest = text;
    while !rest.is_empty() {
        let mut boundary = rest.len().min(CHECK_INTERVAL);
        while !rest.is_char_boundary(boundary) {
            boundary -= 1;
        }
        let (chunk, remainder) = rest.split_at(boundary);
        out.push(chunk)?;
        rest = remainder;
    }
    Ok(out.out)
}

// ---------------------------------------------------------------------------
// Text rendering
// ---------------------------------------------------------------------------

fn findrefs_text(
    rows: &[Reference],
    budget: usize,
    control: &OperationControl,
) -> Result<String, Error> {
    let mut out = TextOut::new(budget, control);
    for reference in rows {
        let caller = reference.caller();
        let dex = caller.id().dex();
        let mut line = String::new();
        // Column 1-4 use text escaping; the targets column is JSON only.
        push_escaped_str(&mut line, &format!("{}:{}", dex.entry_ordinal(), dex.logical_ordinal()));
        line.push_str(SEP);
        push_escaped_units(&mut line, caller.dex().display_name().utf16_units());
        line.push_str(SEP);
        push_escaped_str(&mut line, &caller.id().method_idx().to_string());
        line.push_str(SEP);
        push_escaped_units(&mut line, caller.owner().utf16_units());
        line.push_str("->");
        push_escaped_units(&mut line, caller.name().utf16_units());
        push_prototype_text(&mut line, caller.prototype());
        line.push_str(SEP);
        push_targets_json(&mut line, reference.targets());
        line.push('\n');
        out.push(&line)?;
    }
    Ok(out.out)
}

fn classes_text(
    rows: &[Class],
    budget: usize,
    control: &OperationControl,
) -> Result<String, Error> {
    let mut out = TextOut::new(budget, control);
    for class in rows {
        let id = class.id();
        let dex = id.dex();
        let mut line = String::new();
        push_escaped_str(&mut line, &format!("{}:{}", dex.entry_ordinal(), dex.logical_ordinal()));
        line.push_str(SEP);
        push_escaped_units(&mut line, class.dex().display_name().utf16_units());
        line.push_str(SEP);
        push_escaped_str(&mut line, &id.class_def_idx().to_string());
        line.push_str(SEP);
        push_escaped_str(&mut line, class.descriptor().as_str());
        line.push_str(SEP);
        push_escaped_units(&mut line, class.java_name().utf16_units());
        line.push_str(SEP);
        push_escaped_units(&mut line, class.package().utf16_units());
        line.push_str(SEP);
        push_escaped_units(&mut line, class.simple_name().utf16_units());
        line.push('\n');
        out.push(&line)?;
    }
    Ok(out.out)
}

fn push_prototype_text(line: &mut String, prototype: &crate::model::Prototype) {
    line.push('(');
    for parameter in prototype.parameters() {
        push_escaped_units(line, parameter.utf16_units());
    }
    line.push(')');
    push_escaped_units(line, prototype.return_type().utf16_units());
}

/// The `targets-json` column: a JSON array of target objects with full
/// identity, kind, value and code-unit offsets. JSON escaping only — the
/// consumer splits the first four unescaped separators, then reads this as
/// one JSON document (never `\|` inside).
fn push_targets_json(line: &mut String, targets: &[TargetMatch]) {
    let mut writer = Writer::new();
    writer.begin_array();
    for target in targets {
        dto::write_target_match(&mut writer, target);
    }
    writer.end_array();
    line.push_str(&writer.finish());
}

// ---------------------------------------------------------------------------
// Text escaping (interfaces.md §6)
// ---------------------------------------------------------------------------

/// Escapes a Rust string column: backslash first, then `|`, LF, CR, tab,
/// NUL, other C0/C1 controls; printable characters pass through unchanged.
fn push_escaped_str(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\u0000"),
            character if (character as u32) < 0x20 || (0x7F..=0x9F).contains(&(character as u32)) => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
}

/// Escapes raw UTF-16 units: the same rules as [`push_escaped_str`], plus
/// unpaired surrogates as `\uXXXX` (lowercase) and surrogate pairs as their
/// scalar value. Valid Unicode stays untouched — no replacement characters.
fn push_escaped_units(out: &mut String, units: &[u16]) {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xD800..=0xDBFF).contains(&unit)
            && matches!(units.get(index + 1), Some(low) if (0xDC00..=0xDFFF).contains(low))
        {
            let low = units[index + 1];
            let code =
                0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
            out.push(char::from_u32(code).expect("surrogate pair is a scalar"));
            index += 2;
            continue;
        }
        match unit {
            0x5C => out.push_str("\\\\"),
            0x7C => out.push_str("\\|"),
            0x0A => out.push_str("\\n"),
            0x0D => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x00 => out.push_str("\\u0000"),
            unit if (0xD800..=0xDFFF).contains(&unit) => {
                out.push_str(&format!("\\u{unit:04x}"));
            }
            unit if unit < 0x20 || (0x7F..=0x9F).contains(&unit) => {
                out.push_str(&format!("\\u{unit:04x}"));
            }
            unit => out.push(char::from_u32(u32::from(unit)).expect("BMP scalar")),
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control() -> OperationControl {
        OperationControl::new()
    }

    #[test]
    fn text_escaping_follows_the_frozen_rules() {
        let mut escaped = String::new();
        push_escaped_str(&mut escaped, "a\\b|c\nd\re\tf\0g\u{1}h\u{7f}i\u{9f}j");
        assert_eq!(escaped, "a\\\\b\\|c\\nd\\re\\tf\\u0000g\\u0001h\\u007fi\\u009fj");
        // Printable Unicode passes through untouched.
        let mut plain = String::new();
        push_escaped_str(&mut plain, "中文 ");
        assert_eq!(plain, "中文 ");
    }

    #[test]
    fn utf16_escaping_keeps_pairs_and_escapes_lone_surrogates() {
        let mut escaped = String::new();
        // 😀 = D83D DE00 (a pair), then an unpaired D800.
        push_escaped_units(&mut escaped, &[0xD83D, 0xDE00, b'a' as u16, 0xD800]);
        assert_eq!(escaped, "\u{1F600}a\\ud800");
        // A pipe/backslash inside a DexText column is text-escaped.
        let mut escaped = String::new();
        push_escaped_units(&mut escaped, &[b'a' as u16, 0x7C, 0x5C]);
        assert_eq!(escaped, "a\\|\\\\");
    }

    #[test]
    fn bounded_copy_refuses_to_exceed_the_budget() {
        let error = copy_bounded("0123456789", 4, &control()).unwrap_err();
        assert_eq!(*error.kind(), crate::error::ErrorKind::ResourceLimit);
        assert_eq!(copy_bounded("ok", 16, &control()).unwrap(), "ok");
        // Multi-byte characters are never split mid-UTF-8.
        assert_eq!(copy_bounded("中文中", 12, &control()).unwrap(), "中文中");
    }
}
