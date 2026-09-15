//! APK operations layer: open an input once, then run structured analysis
//! operations over it.
//!
//! Every operation returns the frozen domain types ([`crate::model`]) in a
//! [`Report`], or an [`Error`] with a stable kind — never pre-rendered
//! text, never a partial success. Contract highlights (interfaces.md §4):
//! every dex-backed operation fully inflates and validates every selected
//! root DEX entry before reporting success — an entry that fails is the
//! operation's error even when earlier entries already produced rows —
//! and entries are processed in central-directory order, so the lowest
//! ordinal wins error selection. The former prefix fast path is gone: a
//! prefix cannot certify a complete result.
//!
//! A10 wraps this layer in the Engine/Artifact public API; A11 brings the
//! shared pool and permits. Until then operations process entries
//! sequentially, which keeps budget accounting and error selection exact;
//! the CLI's `--threads` value is accepted and validated but there is
//! nothing to parallelise yet (the per-operation pool is A11's).

use crate::bytes::ControlProbe;
use crate::dex::container::{self, ValidatedDexView};
use crate::dex::{self, ScanOptions};
use crate::error::{Error, ErrorKind};
use crate::bytes::OperationControl;
use crate::model::{
    AnnotationEntry, AnnotationRecord, AnnotationTarget, AnnotationVisibility, ArtifactId, Class,
    ClassDescriptor, ClassFilter, ClassId, ClassMetadata, ClassSelector, DexEntry, DexText,
    Diagnostic, DiagnosticCode, EnclosingRecord, FieldMetadata, InnerClassRecord, MethodMetadata,
    OperationStats, Prototype, Report, Severity, Source, SourceMetadata, Stage,
};
use crate::zip::{self, ArchiveEntry, InputLimits};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rayon::prelude::*;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

/// Per-open and per-operation resource limits the CLI can override
/// (interfaces.md §5 keys enforced by this layer). Unlisted keys (engine
/// bytes, archive/logical entry counts, depth, AXML nodes/attributes, code
/// units) keep their internal defaults until A11/A12 expose them.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// `input-bytes`: the owned snapshot may not exceed this.
    pub max_input_bytes: u64,
    /// `engine-bytes`: the engine-owned active bytes (inputs of artifacts
    /// opened through this engine, dropped with them).
    pub max_engine_owned_bytes: u64,
    /// `entry-bytes`: one entry's actual decoded bytes.
    pub max_entry_bytes: u64,
    /// `decoded-bytes`: per-operation accumulated decoded bytes.
    pub max_total_decoded_bytes: u64,
    /// `table-items`/`string-units`/`result-items`/`locations`/`result-bytes`.
    pub scan: crate::dex::ScanLimits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 512 * 1024 * 1024,
            max_engine_owned_bytes: 2 * 1024 * 1024 * 1024,
            max_entry_bytes: crate::zip::InputLimits::DEFAULT.max_entry_bytes,
            max_total_decoded_bytes: crate::zip::InputLimits::DEFAULT.max_total_decoded_bytes,
            scan: crate::dex::ScanLimits::DEFAULT,
        }
    }
}

impl Limits {
    fn input(&self) -> crate::zip::InputLimits {
        crate::zip::InputLimits {
            max_entry_bytes: self.max_entry_bytes,
            max_total_decoded_bytes: self.max_total_decoded_bytes,
            max_archive_entries: crate::zip::InputLimits::DEFAULT.max_archive_entries,
        }
    }
}

/// `AndroidManifest.xml`, matched on raw entry-name bytes (last wins).
const MANIFEST_NAME: &[u8] = b"AndroidManifest.xml";

/// RAII admission ticket: released on drop, so cancellation or an error
/// path never wedges the engine's top-level queue.
struct Admission<'a> {
    _guard: MutexGuard<'a, ()>,
}

/// Bridges the domain [`OperationControl`] onto the layer-specific probes
/// (zip/scan) and the backend's control token. The dummy flag keeps the
/// `&AtomicBool` alive for probes when the host installed no cancel flag.
struct ControlGuard {
    dummy: AtomicBool,
    flag: Option<Arc<AtomicBool>>,
    deadline: Option<std::time::Instant>,
    #[cfg(feature = "decompile")]
    backend: droidsaw_dex::analysis::Control,
}

impl ControlGuard {
    fn new(control: &OperationControl) -> Self {
        Self {
            dummy: AtomicBool::new(false),
            flag: control.cancel_flag(),
            deadline: control.deadline(),
            #[cfg(feature = "decompile")]
            backend: droidsaw_dex::analysis::Control::new(),
        }
    }

    fn probe(&self) -> ControlProbe<'_> {
        match &self.flag {
            Some(flag) => ControlProbe { cancelled: flag, deadline: self.deadline },
            None => ControlProbe { cancelled: &self.dummy, deadline: self.deadline },
        }
    }
}

/// One opened input: owned bytes, content identity, archive catalog and the
/// selected root DEX entries. Opening validates the archive catalog only —
/// DEX headers and tables are validated per operation.
/// One selected root DEX source: either an archive entry or the whole raw
/// byte stream (InputKind::Dex).
struct Root {
    ordinal: u32,
    raw_name: Vec<u8>,
    source: RootSource,
}

enum RootSource {
    Archive(ArchiveEntry),
    Raw,
}

pub struct Artifact {
    id: ArtifactId,
    bytes: Arc<[u8]>,
    catalog: Option<zip::ArchiveCatalog>,
    roots: Vec<Root>,
    /// The engine runtime this artifact belongs to; operations on a foreign
    /// artifact are rejected (interfaces.md §2).
    runtime: Arc<Runtime>,
    /// Duplicate-entry-name warnings observed at open time, attached to
    /// every operation's report.
    open_diagnostics: Vec<Diagnostic>,
    /// The resource limits this artifact's operations enforce.
    limits: Limits,
}

impl Artifact {
    /// The content identity printed in the JSON envelope.
    pub fn id(&self) -> ArtifactId {
        self.id
    }

    fn byte_len(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }
}

impl Drop for Artifact {
    fn drop(&mut self) {
        // The engine-owned account returns the input bytes; the artifact's
        // other members drop normally.
        self.runtime
            .active_bytes
            .fetch_sub(self.byte_len(), Ordering::Relaxed);
    }
}

/// Opens `path` as an APK: bounded owned snapshot, content id, archive
/// catalog, root DEX selection.
pub(crate) fn open_path(
    path: &Path,
    limits: &Limits,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
) -> Result<Artifact, Error> {
    let mut file = File::open(path)
        .map_err(|error| Error::new(ErrorKind::NotFound).with_context(format!("open {path:?}: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::new(ErrorKind::NotFound).with_context(format!("stat {path:?}: {error}")))?;
    if !metadata.is_file() {
        return Err(Error::new(ErrorKind::UnsupportedFormat)
            .with_context(format!("{path:?} is not a regular file")));
    }
    if metadata.len() > limits.max_input_bytes {
        return Err(Error::resource_limit(format!(
            "{path:?} is {} bytes, above the {} input limit",
            metadata.len(),
            limits.max_input_bytes
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        control.check()?;
        let read = file.read(&mut buffer).map_err(|error| {
            Error::new(ErrorKind::MalformedInput).with_context(format!("read {path:?}: {error}"))
        })?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    // Engine-owned budget: the snapshot reserves its full length until the
    // artifact drops (interfaces.md §2: no waiting on another artifact's
    // drop - insufficient budget fails immediately).
    if runtime.active_bytes.load(Ordering::Relaxed) + bytes.len() as u64
        > limits.max_engine_owned_bytes
    {
        return Err(Error::resource_limit(format!(
            "engine-owned bytes {} + {} would exceed the {} limit",
            runtime.active_bytes.load(Ordering::Relaxed),
            bytes.len(),
            limits.max_engine_owned_bytes
        )));
    }
    let artifact = open_bytes(Arc::from(bytes.into_boxed_slice()), limits, runtime, control)?;
    let mut artifact = artifact;
    artifact.limits = *limits;
    Ok(artifact)
}

/// Opens an already-owned input snapshot (the raw-bytes host path and tests).
pub(crate) fn open_bytes(
    bytes: Arc<[u8]>,
    limits: &Limits,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
) -> Result<Artifact, Error> {
    let _ = control;
    // Engine-owned budget: the snapshot reserves its full length until the
    // artifact drops (interfaces.md §2: no waiting on another artifact's
    // drop - insufficient budget fails immediately).
    let live = runtime.active_bytes.load(Ordering::Relaxed);
    if live + bytes.len() as u64 > limits.max_engine_owned_bytes {
        return Err(Error::resource_limit(format!(
            "engine-owned bytes {live} + {} would exceed the {} limit",
            bytes.len(),
            limits.max_engine_owned_bytes
        )));
    }
    let id = ArtifactId::from_digest(crate::bytes::sha256(&bytes));
    let catalog = zip::parse_catalog(&bytes, &InputLimits::DEFAULT)?;
    let selection = zip::select_root_dexes(&catalog);
    let mut open_diagnostics = Vec::new();
    for duplicate in &selection.duplicates {
        open_diagnostics.push(Diagnostic::new(
            DiagnosticCode::DuplicateEntryName,
            Severity::Warning,
            Stage::Input,
            format!(
                "archive entry name {:?} appears more than once; the first central-directory \
                 record is selected",
                zip::display_name(&duplicate.name)
            ),
        ));
    }
    let roots = selection
        .selected
        .into_iter()
        .map(|entry| Root {
            ordinal: entry.ordinal,
            raw_name: entry.raw_name.clone(),
            source: RootSource::Archive(entry.clone()),
        })
        .collect();
    let artifact = Artifact {
        id,
        bytes,
        catalog: Some(catalog),
        roots,
        runtime: Arc::clone(runtime),
        open_diagnostics,
        limits: *limits,
    };
    runtime.active_bytes.fetch_add(artifact.byte_len(), Ordering::Relaxed);
    Ok(artifact)
}

impl Artifact {
    /// Runs `op` over every selected root entry in ordinal order. Each entry
    /// is fully inflated (shared decode budget) and validated before its
    /// operation runs; the first failing entry aborts with its error — rows
    /// computed from earlier entries do not turn that into a success.
    fn fold_roots<T: Send>(
        &self,
        control: &OperationControl,
        op: impl Fn(&Root, &container::DexEntryViews<'_>, &ControlProbe<'_>) -> Result<Vec<T>, Error>
            + Sync,
    ) -> Result<(Vec<T>, Vec<Diagnostic>), Error> {
        let guard = ControlGuard::new(control);
        let probe = guard.probe();
        let input_limits = self.limits.input();
        let decoded = AtomicU64::new(0);
        // Parallel across entries; results and errors are merged in ordinal
        // order, so the lowest ordinal decides the operation's error and the
        // merged output never depends on scheduling (interfaces.md §4).
        #[allow(clippy::type_complexity)]
        let per_root: Vec<Result<(Vec<T>, Vec<Diagnostic>), Error>> = self
            .roots
            .par_iter()
            .map(|root| {
                let data: &[u8] = match &root.source {
                    RootSource::Archive(entry) => {
                        &zip::read_entry(&self.bytes, entry, &input_limits, &decoded, &probe)?
                    }
                    RootSource::Raw => &self.bytes,
                };
                let (views, entry_integrity) = container::validate_dex_entry(
                    self.id,
                    root.ordinal,
                    &root.raw_name,
                    data,
                    &probe,
                )?;
                let rows = op(root, &views, &probe)?;
                Ok((rows, entry_integrity))
            })
            .collect();
        let mut results = Vec::new();
        let mut integrity = Vec::new();
        for entry in per_root {
            let (rows, entry_integrity) = entry?;
            results.extend(rows);
            integrity.extend(entry_integrity);
        }
        let diagnostics =
            self.open_diagnostics.iter().cloned().chain(integrity.iter().cloned()).collect();
        Ok((results, diagnostics))
    }

    fn require_roots(&self) -> Result<(), Error> {
        if self.roots.is_empty() {
            return Err(Error::new(ErrorKind::NotFound)
                .with_context("the archive contains no root DEX entry to analyse"));
        }
        Ok(())
    }
}

/// The selected logical DEX entries: identity, names, version, header offset.
/// A DEX-less archive yields a successful empty catalog.
pub fn dexes(artifact: &Artifact, control: &OperationControl) -> Result<Report<Vec<DexEntry>>, Error> {
    let (rows, diagnostics) = artifact.fold_roots(control, |_entry, views, _probe| {
        let mut rows = Vec::with_capacity(views.views.len());
        for logical in 0..views.views.len() {
            rows.push(views.dex_entry(logical));
        }
        Ok(rows)
    })?;
    let stats = OperationStats { selected_dexes: rows.len() as u32, ..Default::default() };
    Ok(Report::new(rows, diagnostics, stats))
}

/// Every class definition across all selected DEX entries, in
/// (entry, logical, class_def) order, filtered by Java-name substring. All
/// definitions are kept: the identity is the class_def index, never the
/// descriptor.
pub fn classes(
    artifact: &Artifact,
    filter: &ClassFilter,
    control: &OperationControl,
) -> Result<Report<Vec<Class>>, Error> {
    artifact.require_roots()?;
    let scan_limits = artifact.limits.scan;
    // (class, descriptor) pairs: duplicates are counted across every
    // definition before the filter (a filtered-out duplicate is still a
    // duplicate definition).
    let (pairs, mut diagnostics) = artifact.fold_roots(control, |_entry, views, probe| {
        let mut pairs = Vec::new();
        for (logical, view) in views.views.iter().enumerate() {
            let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
            for class in dex::list_classes(&dex_view, &scan_limits, Some(probe))? {
                let descriptor = class.descriptor().as_str().to_owned();
                pairs.push((class, descriptor));
            }
        }
        Ok(pairs)
    })?;
    let mut descriptor_counts: std::collections::BTreeMap<String, usize> = Default::default();
    let mut rows = Vec::with_capacity(pairs.len());
    for (class, descriptor) in pairs {
        *descriptor_counts.entry(descriptor).or_insert(0) += 1;
        if filter.matches(class.java_name()) {
            rows.push(class);
        }
    }
    for (descriptor, count) in descriptor_counts {
        if count > 1 {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::DuplicateClassDefinition,
                Severity::Warning,
                Stage::Dex,
                format!(
                    "descriptor {descriptor} is defined {count} times; identity is the \
                     (entry, logical, class_def) index, not the name"
                ),
            ));
        }
    }
    // Rows ordered by their (entry, logical, class_def) identity.
    rows.sort_by_key(|class| class.id());
    let stats = OperationStats { result_items: rows.len() as u64, ..Default::default() };
    Ok(Report::new(rows, diagnostics, stats))
}

/// Reference hits for one structured query, in (entry, logical, method_idx)
/// order. An empty result is a success: the class walk still certifies the
/// selected entries' structure.
pub fn references(
    artifact: &Artifact,
    query: &crate::model::ReferenceQuery,
    control: &OperationControl,
) -> Result<Report<Vec<crate::model::Reference>>, Error> {
    artifact.require_roots()?;
    let scan_limits = artifact.limits.scan;
    let (rows, diagnostics) = artifact.fold_roots(control, |_entry, views, probe| {
        let mut rows = Vec::new();
        for (logical, view) in views.views.iter().enumerate() {
            let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
            let options =
                ScanOptions { limits: scan_limits, control: Some(probe), prefilter: true };
            rows.extend(dex::scan_references(&dex_view, query, &options)?);
        }
        Ok(rows)
    })?;
    let stats = OperationStats {
        result_items: rows.len() as u64,
        matched_targets: rows.iter().map(|row| row.targets().len() as u64).sum(),
        ..Default::default()
    };
    Ok(Report::new(rows, diagnostics, stats))
}

/// Decompiles one class through the checked backend path. `selector` is a
/// descriptor (optionally pinned to one logical DEX) or a full identity;
/// the default descriptor resolution takes the first (entry, logical,
/// class_def) definition and reports duplicates.
#[cfg(feature = "decompile")]
pub fn decompile(
    artifact: &Artifact,
    selector: &ClassSelector,
    control: &OperationControl,
) -> Result<Report<Source>, Error> {
    artifact.require_roots()?;
    // Resolution pass: inflate + validate entries in ordinal order until the
    // selector hits. A broken entry before the hit is the operation's error;
    // entries after the hit are validated in the completion pass below (a
    // complete success certifies every selected entry).
    struct Resolved {
        entry_index: usize,
        logical: usize,
        class_def_idx: u32,
        duplicates: usize,
    }
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let decoded = AtomicU64::new(0);
    let mut resolution: Option<Resolved> = None;
    let mut integrity = Vec::new();
    for (entry_index, root) in artifact.roots.iter().enumerate() {
        probe.check()?;
        #[allow(unused_assignments)] // Raw input never fills the buffer
        #[allow(unused_assignments)] // Raw input never fills the buffer
        let mut data_buffer = None;
        let data: &[u8] = match &root.source {
            RootSource::Archive(entry) => {
                data_buffer = Some(zip::read_entry(
                    &artifact.bytes,
                    entry,
                    &artifact.limits.input(),
                    &decoded,
                    &probe,
                )?);
                data_buffer.as_deref().expect("just assigned")
            }
            RootSource::Raw => &artifact.bytes,
        };
        let (views, entry_integrity) =
            container::validate_dex_entry(artifact.id, root.ordinal, &root.raw_name, data, &probe)?;
        integrity.extend(entry_integrity);
        'members: for (logical, view) in views.views.iter().enumerate() {
            match selector {
                ClassSelector::Descriptor(descriptor, pinned) => {
                    if let Some(pinned_id) = pinned
                        && view.id() != *pinned_id
                    {
                        continue;
                    }
                    let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
                    let hits =
                        dex::locate_class(&dex_view, descriptor, &artifact.limits.scan, Some(&probe))?;
                    if let Some(&class_def_idx) = hits.first() {
                        resolution = Some(Resolved {
                            entry_index,
                            logical,
                            class_def_idx,
                            duplicates: hits.len().saturating_sub(1),
                        });
                        break 'members;
                    }
                }
                ClassSelector::Id(class_id) => {
                    if class_id.dex().artifact() != artifact.id {
                        return Err(Error::invalid_query(format!(
                            "class id {class_id:?} belongs to a different artifact"
                        )));
                    }
                    if views.views[logical].id() == class_id.dex() {
                        resolution = Some(Resolved {
                            entry_index,
                            logical,
                            class_def_idx: class_id.class_def_idx(),
                            duplicates: 0,
                        });
                        break 'members;
                    }
                }
            }
        }
        if resolution.is_some() {
            break;
        }
    }
    let Some(resolved) = resolution else {
        let diagnostics = artifact
            .open_diagnostics
            .iter()
            .cloned()
            .chain(integrity.iter().cloned())
            .collect();
        return Err(Error::new(ErrorKind::NotFound)
            .with_context("no selected DEX entry defines this class")
            .with_diagnostics(diagnostics));
    };
    let mut diagnostics: Vec<Diagnostic> =
        artifact.open_diagnostics.iter().cloned().chain(integrity.iter().cloned()).collect();
    if resolved.duplicates > 0 {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::DuplicateClassDefinition,
            Severity::Warning,
            Stage::Dex,
            format!(
                "the descriptor is defined {} times; the first (entry, logical, class_def) \
                 identity was decompiled",
                resolved.duplicates + 1
            ),
        ));
    }

    // Backend parse + checked decompile over the resolved entry's bytes
    // (041 members go through the operation-local scratch normalization).
    let root = &artifact.roots[resolved.entry_index];
    #[allow(unused_assignments)] // Raw input never fills the buffer
    let mut data_buffer = None;
    let data: &[u8] = match &root.source {
        RootSource::Archive(entry) => {
            data_buffer = Some(zip::read_entry(
                &artifact.bytes,
                entry,
                &artifact.limits.input(),
                &decoded,
                &probe,
            )?);
            data_buffer.as_deref().expect("just assigned")
        }
        RootSource::Raw => &artifact.bytes,
    };
    let (views, entry_integrity) =
        container::validate_dex_entry(artifact.id, root.ordinal, &root.raw_name, data, &probe)?;
    diagnostics.extend(entry_integrity);
    let view = &views.views[resolved.logical];
    let scratch = container::backend_scratch(view, &integrity);
    let backend_bytes: &[u8] = match &scratch {
        Some(scratch_view) => &scratch_view.bytes,
        None => view.bytes(),
    };
    let budget = droidsaw_dex::analysis::Budget::default();
    let parsed = droidsaw_dex::analysis::parse_for_analysis(
        backend_bytes,
        &droidsaw_dex::analysis::ParseOptions::default(),
        &budget,
        &guard.backend,
    )
    .map_err(|error| {
        Error::new(ErrorKind::MalformedInput)
            .with_context(format!("backend parse: {error}"))
            .with_diagnostics(diagnostics.clone())
    })?;
    let report = droidsaw_dex::analysis::decompile_checked(
        &parsed,
        resolved.class_def_idx as usize,
        &droidsaw_dex::analysis::EmitOptions::default(),
        &budget,
        &guard.backend,
    )
    .map_err(|error| {
        Error::new(ErrorKind::MalformedInput)
            .with_context(format!("backend decompile: {error}"))
            .with_diagnostics(diagnostics.clone())
    })?;

    let class_def = &parsed.dex().class_defs[resolved.class_def_idx as usize];
    let descriptor_text =
        parsed.dex().get_type_descriptor(class_def.class_idx).unwrap_or("L?;").to_owned();
    let entry_row = views.dex_entry(resolved.logical);
    let class = build_class(&entry_row, view, resolved.class_def_idx, &descriptor_text);
    let metadata = map_metadata(&report.metadata);
    let text = normalize_source_text(&report.source);
    let source = Source::new(class, text, metadata);
    for backend_diag in &report.diagnostics {
        diagnostics.push(
            Diagnostic::new(
                DiagnosticCode::DecompilationNotice,
                Severity::Warning,
                Stage::Decompile,
                format!("{:?}: {}", backend_diag.code, backend_diag.message),
            )
            .with_dex(view.id()),
        );
    }
    match &report.completeness {
        droidsaw_dex::analysis::Completeness::Complete => {
            let stats = OperationStats { result_items: 1, ..Default::default() };
            Ok(Report::new(source, diagnostics, stats))
        }
        droidsaw_dex::analysis::Completeness::Incomplete { reasons } => Err(Error::new(
            ErrorKind::IncompleteDecompilation,
        )
        .with_context(format!("incomplete decompilation: {reasons:?}"))
        .with_diagnostics(diagnostics)
        .with_partial_source(source)),
    }
}

/// The decoded manifest: last same-name entry wins. Requires only that one
/// entry's bytes; DEX entries are not touched.
#[cfg(feature = "manifest")]
pub fn manifest(
    artifact: &Artifact,
    control: &OperationControl,
) -> Result<Report<crate::manifest::Manifest>, Error> {
    let catalog = artifact.catalog.as_ref().ok_or_else(|| {
        Error::new(ErrorKind::NotFound).with_context("a raw DEX input has no AndroidManifest.xml")
    })?;
    let entry = catalog
        .entries
        .iter()
        .rev()
        .find(|entry| entry.raw_name.as_slice() == MANIFEST_NAME)
        .ok_or_else(|| {
            Error::new(ErrorKind::NotFound).with_context("no AndroidManifest.xml entry in the APK")
        })?;
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let decoded = AtomicU64::new(0);
    let bytes = zip::read_entry(&artifact.bytes, entry, &artifact.limits.input(), &decoded, &probe)?;
    let report = crate::manifest::decode_manifest_entry(
        &bytes,
        &crate::manifest::XmlDecodeLimits::default(),
        control,
    )?;
    let diagnostics = report
        .diagnostics
        .iter()
        .cloned()
        .chain(artifact.open_diagnostics.iter().cloned())
        .collect();
    Ok(Report::new(
        report.value,
        diagnostics,
        OperationStats { result_items: 1, ..Default::default() },
    ))
}

// --- mapping helpers ---------------------------------------------------------

#[cfg(feature = "decompile")]
fn build_class(
    entry: &DexEntry,
    view: &ValidatedDexView<'_>,
    class_def_idx: u32,
    descriptor_text: &str,
) -> Class {
    let descriptor =
        ClassDescriptor::from_normalized(descriptor_text.to_owned()).unwrap_or_else(|_| {
            // The backend hands back what the DEX carries; a malformed
            // descriptor keeps the identity but renders through a valid
            // shell. `locate_class` rejects such files earlier, so this is
            // defensive only.
            ClassDescriptor::from_normalized("L?;".to_owned()).expect("L?; is a valid descriptor")
        });
    Class::new(ClassId::new(view.id(), class_def_idx), entry.clone(), descriptor)
}

#[cfg(feature = "decompile")]
fn map_metadata(metadata: &droidsaw_dex::analysis::BackendMetadata) -> SourceMetadata {
    let class = ClassMetadata {
        access_flags: metadata.access_flags,
        super_class: metadata.super_descriptor.as_deref().map(DexText::from_str_lossless),
        interfaces: metadata
            .interfaces
            .iter()
            .map(|text| DexText::from_str_lossless(text))
            .collect(),
        source_file: metadata.source_file.as_deref().map(DexText::from_str_lossless),
        generic_signature: metadata.generic_signature.as_deref().map(DexText::from_str_lossless),
        enclosing: metadata.enclosing.as_ref().map(|enclosing| EnclosingRecord {
            outer_class: enclosing.class.as_deref().map(DexText::from_str_lossless),
            enclosing_method: enclosing.method.as_deref().map(|text| {
                // The backend renders `name(proto)ret`; kept verbatim as the
                // method record — the lossless text is the identity here.
                (
                    DexText::from_str_lossless(text),
                    DexText::from_str_lossless(""),
                    Prototype::default(),
                )
            }),
        }),
        inner_classes: metadata
            .inner_class
            .as_ref()
            .map(|inner| {
                vec![InnerClassRecord {
                    inner_class: DexText::from_str_lossless(""),
                    outer_class: inner.name.as_deref().map(DexText::from_str_lossless),
                    inner_name: inner.name.as_deref().map(DexText::from_str_lossless),
                    access_flags: inner.access_flags,
                }]
            })
            .unwrap_or_default(),
    };
    let annotations = metadata
        .annotations
        .iter()
        .map(|report| AnnotationEntry {
            target: map_annotation_target(report.target),
            annotation: AnnotationRecord::new(
                map_annotation_visibility(report.visibility),
                DexText::from_str_lossless(&report.type_descriptor),
                Vec::new(),
                render_annotation_elements(&report.elements),
            ),
        })
        .collect();
    let fields = metadata
        .instance_field_reports
        .iter()
        .map(|report| FieldMetadata {
            name: DexText::from_str_lossless(&report.name),
            field_type: DexText::from_str_lossless(&report.type_descriptor),
            access_flags: report.access_flags,
            generic_signature: None,
            initial_value: None,
        })
        .collect();
    let methods = metadata
        .method_reports
        .iter()
        .map(|report| MethodMetadata {
            name: DexText::from_str_lossless(&report.name),
            prototype: prototype_from_descriptor(&report.prototype),
            access_flags: report.access_flags,
            generic_signature: None,
            throws: Vec::new(),
            annotations: Vec::new(),
            parameter_signatures: Vec::new(),
            debug: None,
        })
        .collect();
    SourceMetadata { class, annotations, fields, methods }
}

#[cfg(feature = "decompile")]
fn map_annotation_target(target: droidsaw_dex::analysis::AnnotationTarget) -> AnnotationTarget {
    use droidsaw_dex::analysis::AnnotationTarget as Backend;
    match target {
        Backend::Class => AnnotationTarget::Class,
        Backend::Field { field_idx } => AnnotationTarget::Field { index: field_idx as usize },
        Backend::Method { method_idx } => AnnotationTarget::Method { index: method_idx as usize },
        Backend::Parameter { method_idx, index } => AnnotationTarget::Parameter {
            method_index: method_idx as usize,
            parameter_index: index as usize,
        },
    }
}

#[cfg(feature = "decompile")]
fn map_annotation_visibility(
    visibility: droidsaw_dex::analysis::AnnotationVisibility,
) -> AnnotationVisibility {
    use droidsaw_dex::analysis::AnnotationVisibility as Backend;
    match visibility {
        Backend::Build => AnnotationVisibility::Build,
        Backend::Runtime => AnnotationVisibility::Runtime,
        Backend::System => AnnotationVisibility::System,
    }
}

fn render_annotation_elements(elements: &[(String, String)]) -> String {
    elements
        .iter()
        .map(|(name, value)| format!("{name} = {value}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parses a backend prototype descriptor `(params)ret` into the structured
/// form. An unparseable text keeps the raw string as the single parameter —
/// the lossless record beats a silently empty prototype.
#[cfg(feature = "decompile")]
fn prototype_from_descriptor(descriptor: &str) -> Prototype {
    let Some((params_text, ret)) = descriptor.split_once(')') else {
        return Prototype::new(
            vec![DexText::from_str_lossless(descriptor)],
            DexText::from_str_lossless(""),
        );
    };
    let params_text = params_text.trim_start_matches('(');
    let mut parameters = Vec::new();
    let mut rest = params_text;
    while !rest.is_empty() {
        let consumed = match rest.as_bytes()[0] {
            b'L' => rest.find(';').map(|semi| semi + 1).unwrap_or(rest.len()),
            b'[' => 1 + prototype_component_size(&rest[1..]),
            _ => 1,
        };
        parameters.push(DexText::from_str_lossless(&rest[..consumed]));
        rest = &rest[consumed..];
    }
    Prototype::new(parameters, DexText::from_str_lossless(ret))
}

/// Length of one non-array component at the head of `rest` (1 for
/// primitives, up to and including the `;` for class types).
#[cfg(feature = "decompile")]
fn prototype_component_size(rest: &str) -> usize {
    match rest.as_bytes().first() {
        Some(b'L') => rest.find(';').map(|semi| semi + 1).unwrap_or(rest.len()),
        _ => 1,
    }
}

/// UTF-8, LF line endings, exactly one trailing LF.
#[cfg(feature = "decompile")]
fn normalize_source_text(source: &str) -> Arc<str> {
    let trimmed = source.trim_end_matches(['\n', '\r']);
    Arc::from(format!("{trimmed}\n").as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dex::tests::const_string_fixture;
    use crate::query::{self, MatchMode};
    use crate::zip::tests::{build_zip, temp_apk};
    use std::fs;

    fn no_control() -> OperationControl {
        OperationControl::new()
    }

    /// A fresh engine runtime for tests (each call = its own account).
    fn test_runtime() -> Arc<Runtime> {
        Arc::new(Runtime::default())
    }

    /// G02 bytes (static initial values), copied from the contract fixtures.
    fn g02_dex() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/contracts/inputs/g02-static-initializers.dex"
        ))
        .expect("g02 fixture")
    }

    #[test]
    fn references_run_end_to_end_on_a_synthetic_apk() {
        let first = const_string_fixture(2);
        let second = const_string_fixture(1);
        let zip = build_zip(&[
            ("classes.dex", &first, true),
            ("classes2.dex", &second, false),
            ("AndroidManifest.xml", b"<manifest/>".as_slice(), false),
        ]);
        let path = temp_apk("a07-refs", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let query = query::string_query("Authorization", MatchMode::Literal, &Default::default())
            .unwrap();
        let report = references(&artifact, &query, &no_control()).unwrap();
        assert!(!report.value().is_empty(), "fixture strings must hit");
        // central-directory order: every row of classes.dex precedes classes2.dex
        let first_ordinal = report.value()[0].caller().id().dex().entry_ordinal();
        let all_ordinals: Vec<u32> =
            report.value().iter().map(|row| row.caller().id().dex().entry_ordinal()).collect();
        assert!(
            all_ordinals.windows(2).all(|pair| pair[0] <= pair[1]),
            "rows must be merged in entry-ordinal order"
        );
        assert_eq!(first_ordinal, 0);
        // deterministic across runs
        let again = references(&artifact, &query, &no_control()).unwrap();
        assert_eq!(format!("{:?}", report.value()), format!("{:?}", again.value()));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dexless_archives_split_success_and_notfound_by_operation() {
        let zip = build_zip(&[("AndroidManifest.xml", b"<manifest/>".as_slice(), false)]);
        let path = temp_apk("a07-dexless", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let dex_rows = dexes(&artifact, &no_control()).unwrap();
        assert!(dex_rows.value().is_empty(), "dexes on a dex-less APK is an empty catalog");
        let query =
            query::string_query("Authorization", MatchMode::Literal, &Default::default()).unwrap();
        let error = references(&artifact, &query, &no_control()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::NotFound);
        let class_error = classes(&artifact, &ClassFilter::none(), &no_control()).unwrap_err();
        assert_eq!(*class_error.kind(), ErrorKind::NotFound);
        fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn g02_static_initializers_survive_the_integration() {
        let dex = g02_dex();
        let zip = build_zip(&[("classes.dex", &dex, true)]);
        let path = temp_apk("a07-g02", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let selector = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("Lexample/Statics;".to_owned()).unwrap(),
            None,
        );
        let report = decompile(&artifact, &selector, &no_control()).unwrap();
        let text = report.value().text();
        assert!(text.contains("FIRST = 11"), "FIRST initializer missing:\n{text}");
        assert!(text.contains("SECOND = 22"), "SECOND initializer missing:\n{text}");
        assert!(text.contains("SECOND"), "getSecond must read SECOND:\n{text}");
        assert_eq!(report.value().class().descriptor().as_str(), "Lexample/Statics;");
        fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn zero_checksum_dex_decompiles_with_a_warning() {
        // G03: the G02 bytes with the checksum/signature window zeroed.
        let mut dex = g02_dex();
        dex[8..32].fill(0);
        let zip = build_zip(&[("classes.dex", &dex, true)]);
        let path = temp_apk("a07-g03", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let selector = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("Lexample/Statics;".to_owned()).unwrap(),
            None,
        );
        let report = decompile(&artifact, &selector, &no_control()).unwrap();
        assert!(report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == DiagnosticCode::DexChecksumMismatch));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn classes_lists_all_definitions_and_flags_duplicates() {
        // One descriptor defined in two different DEX entries.
        let first = const_string_fixture(1);
        let zip = build_zip(&[("classes.dex", &first, true), ("classes2.dex", &first, true)]);
        let path = temp_apk("a07-dup-classes", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let report = classes(&artifact, &ClassFilter::none(), &no_control()).unwrap();
        assert_eq!(report.value().len(), 2, "both definitions are listed");
        let ids: Vec<u32> = report.value().iter().map(|class| class.id().class_def_idx()).collect();
        assert_eq!(ids, [0, 0], "both are class_def 0 of their own DEX");
        let dexes_of: Vec<u32> =
            report.value().iter().map(|class| class.id().dex().entry_ordinal()).collect();
        assert_eq!(dexes_of, [0, 1]);
        assert!(report
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code() == DiagnosticCode::DuplicateClassDefinition));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn manifest_decodes_through_the_structured_path() {
        let dex = const_string_fixture(1);
        let zip = build_zip(&[
            ("AndroidManifest.xml", b"<manifest/>".as_slice(), false),
            ("classes.dex", &dex, true),
        ]);
        let path = temp_apk("a07-manifest", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let report = manifest(&artifact, &no_control()).unwrap();
        let xml = report
            .value()
            .to_xml(&crate::manifest::XmlRenderOptions::default(), &no_control())
            .unwrap();
        assert!(xml.contains("<manifest"), "rendered manifest: {xml}");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn cross_engine_artifacts_are_rejected() {
        let apk_path = {
            let dex = const_string_fixture(1);
            let zip = build_zip(&[("classes.dex", &dex, true)]);
            temp_apk("a11-cross-engine", &zip)
        };
        let engine_a = Engine::new(EngineOptions::default()).unwrap();
        let engine_b = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine_a
            .open_path(&apk_path, InputKind::Apk, &no_control())
            .expect("open on engine A");
        let query = query::string_query("Authorization", MatchMode::Literal, &Default::default())
            .expect("query");
        let error = match engine_b.references(&artifact, &query, &no_control()) {
            Err(error) => error,
            Ok(_) => panic!("foreign artifact must be rejected"),
        };
        assert!(matches!(error.kind(), ErrorKind::InvalidQuery));
        // The owning engine still works.
        assert!(engine_a.references(&artifact, &query, &no_control()).is_ok());
        std::fs::remove_file(&apk_path).unwrap();
    }

    #[test]
    fn engine_owned_bytes_account_tracks_and_releases() {
        let runtime = test_runtime();
        let dex = const_string_fixture(1);
        let zip = build_zip(&[("classes.dex", &dex, true)]);
        let limits = Limits {
            max_input_bytes: u64::MAX,
            max_engine_owned_bytes: 64,
            ..Limits::default()
        };
        // 64-byte engine budget: opening the (larger) APK fails immediately.
        let error = match open_bytes(
            Arc::from(zip.clone().into_boxed_slice()),
            &limits,
            &runtime,
            &no_control(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("open must fail the engine-owned budget"),
        };
        assert!(matches!(error.kind(), ErrorKind::ResourceLimit));
        assert_eq!(runtime.active_bytes.load(Ordering::Relaxed), 0, "nothing retained");
        // A generous budget opens and retains; dropping releases.
        let artifact = open_bytes(
            Arc::from(zip.into_boxed_slice()),
            &Limits::default(),
            &runtime,
            &no_control(),
        )
        .unwrap();
        assert_eq!(
            runtime.active_bytes.load(Ordering::Relaxed),
            artifact.byte_len(),
            "retained input bytes are accounted"
        );
        drop(artifact);
        assert_eq!(runtime.active_bytes.load(Ordering::Relaxed), 0, "drop releases");
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn getclass_pinned_dex_selects_across_entries() {
        // Fixture0 lives in both entries; Fixture1 only in classes2.dex.
        let first = const_string_fixture(1);
        let second = const_string_fixture(2);
        let zip = build_zip(&[("classes.dex", &first, true), ("classes2.dex", &second, true)]);
        let path = temp_apk("a07-pin", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let catalog = dexes(&artifact, &no_control()).unwrap();
        assert_eq!(catalog.value().len(), 2);
        let pinned = catalog.value()[1].id();
        let selector = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("LFixture1;".to_owned()).unwrap(),
            Some(pinned),
        );
        let report = decompile(&artifact, &selector, &no_control()).unwrap();
        assert!(report.value().text().contains("Fixture1"));
        // An unpinned descriptor resolution still finds the first definition.
        let unpinned = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("LFixture0;".to_owned()).unwrap(),
            None,
        );
        let report = decompile(&artifact, &unpinned, &no_control()).unwrap();
        assert!(report.value().text().contains("Fixture0"));
        // A selector pinned to the OTHER entry cannot see Fixture1 there.
        let other = catalog.value()[0].id();
        let wrong = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("LFixture1;".to_owned()).unwrap(),
            Some(other),
        );
        let error = decompile(&artifact, &wrong, &no_control()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::NotFound);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn named_entries_win_over_fallback_and_junk_dex_fails_loudly() {
        let good = const_string_fixture(1);
        let zip = build_zip(&[("app.dex", &good, true), ("classes.dex", &good, true)]);
        let path = temp_apk("a07-named", &zip);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let query =
            query::string_query("Authorization", MatchMode::Literal, &Default::default()).unwrap();
        let report = references(&artifact, &query, &no_control()).unwrap();
        assert!(
            report
                .value()
                .iter()
                .all(|row| row.caller().id().dex().entry_ordinal() == 1),
            "the classes*.dex entry (CD ordinal 1) suppresses the app.dex fallback"
        );
        fs::remove_file(&path).unwrap();

        let junk = build_zip(&[
            ("classes.dex", b"JUNKJUNKJUNK".as_slice(), false),
            ("classes2.dex", &good, true),
        ]);
        let path = temp_apk("a07-junk", &junk);
        let artifact = open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let error = references(&artifact, &query, &no_control()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput);
        fs::remove_file(&path).unwrap();
    }
}


// ---------------------------------------------------------------------------
// Public Engine API (interfaces.md §2; A11 adds the pool/permits runtime)
// ---------------------------------------------------------------------------

/// Explicit input kind: the engine never guesses from file extensions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    Apk,
    Dex,
}

/// Engine construction options. A11 extends this with the runtime
/// limits/pool surface; the current shape carries the default limits.
#[derive(Clone, Copy, Debug, Default)]
pub struct EngineOptions {
    pub limits: Limits,
}

/// Shared engine runtime: serial top-level admission plus the engine-owned
/// active-bytes account. Clones share one runtime (interfaces.md §2: the
/// Engine is a cloneable handle over one private runtime).
#[derive(Debug, Default)]
pub(crate) struct Runtime {
    /// Serial top-level admission: held for the duration of one operation.
    /// Waiters poll with a bounded condvar timeout so a cancelled or
    /// deadline-expired host never queues forever (interfaces.md §5).
    admission: Mutex<()>,
    /// Engine-owned active bytes (inputs + catalogs of artifacts opened
    /// through this engine, dropped with the artifact).
    active_bytes: AtomicU64,
}

/// A long-lived analysis engine: holds the runtime limits and hands out
/// [`Artifact`] handles. Cloning shares one runtime and one admission.
#[derive(Clone, Debug)]
pub struct Engine {
    options: EngineOptions,
    runtime: Arc<Runtime>,
}

impl Engine {
    pub fn new(options: EngineOptions) -> Result<Engine, Error> {
        Ok(Engine { options, runtime: Arc::new(Runtime::default()) })
    }

    /// Serial top-level admission (interfaces.md §5): a caller waits for the
    /// admission lock with a bounded poll so its own cancel flag and deadline
    /// are honored while queued. FIFO order is explicitly not promised.
    fn admit(&self, control: &OperationControl) -> Result<Admission<'_>, Error> {
        loop {
            control.check()?;
            match self.runtime.admission.try_lock() {
                Ok(guard) => return Ok(Admission { _guard: guard }),
                Err(TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(8));
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(Error::new(ErrorKind::MalformedInput)
                        .with_context("engine runtime poisoned by a panic in another operation"));
                }
            }
        }
    }

    /// Opens an APK archive or a raw DEX byte stream from the filesystem.
    pub fn open_path(
        &self,
        path: impl AsRef<Path>,
        kind: InputKind,
        control: &OperationControl,
    ) -> Result<Artifact, Error> {
        match kind {
            InputKind::Apk => {
                open_path(path.as_ref(), &self.options.limits, &self.runtime, control)
            }
            InputKind::Dex => {
                open_dex_path(path.as_ref(), &self.options.limits, &self.runtime, control)
            }
        }
    }

    /// Opens an owned byte snapshot as an APK archive or raw DEX.
    pub fn open_bytes(
        &self,
        bytes: Arc<[u8]>,
        kind: InputKind,
        control: &OperationControl,
    ) -> Result<Artifact, Error> {
        match kind {
            InputKind::Apk => open_bytes(bytes, &self.options.limits, &self.runtime, control),
            InputKind::Dex => open_dex_bytes(bytes, &self.runtime, control),
        }
    }

    fn check_ownership(&self, artifact: &Artifact) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.runtime, &artifact.runtime) {
            return Err(Error::invalid_query(
                "this artifact belongs to a different engine; reopen it with the same engine",
            ));
        }
        Ok(())
    }

    pub fn dexes(
        &self,
        artifact: &Artifact,
        control: &OperationControl,
    ) -> Result<Report<Vec<DexEntry>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        dexes(artifact, control)
    }

    pub fn classes(
        &self,
        artifact: &Artifact,
        filter: &ClassFilter,
        control: &OperationControl,
    ) -> Result<Report<Vec<Class>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        classes(artifact, filter, control)
    }

    pub fn references(
        &self,
        artifact: &Artifact,
        query: &crate::model::ReferenceQuery,
        control: &OperationControl,
    ) -> Result<Report<Vec<crate::model::Reference>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        references(artifact, query, control)
    }

    #[cfg(feature = "decompile")]
    pub fn decompile(
        &self,
        artifact: &Artifact,
        selector: &ClassSelector,
        control: &OperationControl,
    ) -> Result<Report<Source>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        decompile(artifact, selector, control)
    }

    #[cfg(feature = "manifest")]
    pub fn manifest(
        &self,
        artifact: &Artifact,
        control: &OperationControl,
    ) -> Result<Report<crate::manifest::Manifest>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        manifest(artifact, control)
    }
}

/// Opens a raw DEX file from the filesystem (InputKind::Dex).
fn open_dex_path(
    path: &Path,
    limits: &Limits,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
) -> Result<Artifact, Error> {
    let mut file =
        File::open(path).map_err(|error| Error::new(ErrorKind::NotFound).with_context(format!("open {path:?}: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::new(ErrorKind::NotFound).with_context(format!("stat {path:?}: {error}")))?;
    if !metadata.is_file() {
        return Err(Error::new(ErrorKind::UnsupportedFormat).with_context(format!("{path:?} is not a regular file")));
    }
    if metadata.len() > limits.max_input_bytes {
        return Err(Error::resource_limit(format!(
            "{path:?} is {} bytes, above the {} input limit",
            metadata.len(),
            limits.max_input_bytes
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut buffer = [0u8; 64 * 1024];
    loop {
        control.check()?;
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::new(ErrorKind::MalformedInput).with_context(format!("read {path:?}: {error}")))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    open_dex_bytes(Arc::from(bytes.into_boxed_slice()), runtime, control)
}

/// Opens an owned raw DEX byte stream: entry ordinal 0, display name
/// `<memory.dex>` (interfaces.md §1).
fn open_dex_bytes(
    bytes: Arc<[u8]>,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
) -> Result<Artifact, Error> {
    let _ = control;
    let id = ArtifactId::from_digest(crate::bytes::sha256(&bytes));
    let roots = vec![Root { ordinal: 0, raw_name: b"<memory.dex>".to_vec(), source: RootSource::Raw }];
    let artifact = Artifact {
        id,
        bytes,
        catalog: None,
        roots,
        runtime: Arc::clone(runtime),
        open_diagnostics: Vec::new(),
        limits: Limits::default(),
    };
    runtime.active_bytes.fetch_add(artifact.byte_len(), Ordering::Relaxed);
    Ok(artifact)
}
