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
//! ordinal wins error selection.
//!
//! Entry decoding runs in parallel across the selected roots (on the
//! engine's worker pool when `EngineOptions::threads` is set), but the
//! fold's budget is reserved serially in ordinal order before any decode
//! starts, and results, diagnostics and error selection are merged in
//! ordinal order, so the merged output never depends on scheduling.

use crate::bytes::ControlProbe;
use crate::dex::container;
#[cfg(feature = "decompile")]
use crate::dex::container::ValidatedDexView;
use crate::dex::{self, ScanOptions};
use crate::error::{Error, ErrorKind};
use crate::bytes::OperationControl;
#[cfg(feature = "decompile")]
use crate::model::{
    AnnotationEntry, AnnotationRecord, AnnotationTarget, AnnotationVisibility, ArtifactId, Class,
    ClassDescriptor, ClassFilter, ClassId, ClassMetadata, ClassSelector, DexEntry, DexText,
    Diagnostic, DiagnosticCode, EnclosingRecord, FieldMetadata, InnerClassRecord, MethodMetadata,
    OperationStats, Prototype, Report, Severity, Source, SourceMetadata, Stage,
};
#[cfg(not(feature = "decompile"))]
use crate::model::{ArtifactId, Class, ClassFilter, DexEntry, DexText, Diagnostic,
    DiagnosticCode, OperationStats, Prototype, Report, Severity, Stage};
use crate::zip::{self, ArchiveEntry};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use rayon::prelude::*;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

/// Per-open and per-operation resource limits the CLI can override
/// (interfaces.md §5 keys enforced by this layer). Unlisted keys (logical
/// dex count, code units) keep their internal defaults.
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
    /// `entries`: the central-directory entry count cap, enforced inside the
    /// directory walk.
    pub max_archive_entries: usize,
    /// `depth`/`xml-nodes`/`xml-attributes` (and the manifest-side string-unit
    /// budget) for manifest decoding.
    #[cfg(feature = "manifest")]
    pub manifest: crate::manifest::XmlDecodeLimits,
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
            max_archive_entries: crate::zip::InputLimits::DEFAULT.max_archive_entries,
            #[cfg(feature = "manifest")]
            manifest: crate::manifest::XmlDecodeLimits::default(),
            scan: crate::dex::ScanLimits::DEFAULT,
        }
    }
}

impl Limits {
    fn input(&self) -> crate::zip::InputLimits {
        crate::zip::InputLimits {
            max_entry_bytes: self.max_entry_bytes,
            max_total_decoded_bytes: self.max_total_decoded_bytes,
            max_archive_entries: self.max_archive_entries,
        }
    }
}

/// `AndroidManifest.xml`, matched on raw entry-name bytes (last wins).
#[cfg(feature = "manifest")]
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
            backend: droidsaw_dex::analysis::Control::from_cancel_flag(
                control.cancel_flag().unwrap_or_default(),
            ),
        }
    }

    fn probe(&self) -> ControlProbe<'_> {
        match &self.flag {
            Some(flag) => ControlProbe { cancelled: flag, deadline: self.deadline },
            None => ControlProbe { cancelled: &self.dummy, deadline: self.deadline },
        }
    }

    /// The backend budget derived from the host control: the same deadline,
    /// plus an input-length cap for the bytes being parsed.
    #[cfg(feature = "decompile")]
    fn backend_budget(&self, input_len: u64) -> droidsaw_dex::analysis::Budget {
        droidsaw_dex::analysis::Budget { deadline: self.deadline, max_input_bytes: Some(input_len) }
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

/// Atomically reserves `len` bytes against the engine-owned budget. The
/// check and the add are one CAS loop, so concurrent opens cannot both pass
/// the same headroom the way a load-compare-then-add sequence allowed.
fn reserve_bytes(runtime: &Runtime, len: u64, max: u64) -> Result<(), Error> {
    let mut current = runtime.active_bytes.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(len) else {
            return Err(Error::resource_limit(format!(
                "engine-owned bytes {current} + {len} overflow the account"
            )));
        };
        if next > max {
            return Err(Error::resource_limit(format!(
                "engine-owned bytes {current} + {len} would exceed the {max} limit"
            )));
        }
        match runtime.active_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
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
    let bytes = read_path_snapshot(path, limits.max_input_bytes, control)?;
    open_bytes(bytes, limits, runtime, control)
}

fn read_path_snapshot(
    path: &Path,
    max_bytes: u64,
    control: &OperationControl,
) -> Result<Arc<[u8]>, Error> {
    control.check()?;
    let mut file = File::open(path)
        .map_err(|error| Error::new(ErrorKind::NotFound).with_context(format!("open {path:?}: {error}")))?;
    let metadata = file.metadata()
        .map_err(|error| Error::new(ErrorKind::NotFound).with_context(format!("stat {path:?}: {error}")))?;
    if !metadata.is_file() {
        return Err(Error::new(ErrorKind::UnsupportedFormat)
            .with_context(format!("{path:?} is not a regular file")));
    }
    if metadata.len() > max_bytes {
        return Err(Error::resource_limit(format!("{path:?} exceeds the {max_bytes} input limit")));
    }
    read_snapshot(&mut file, max_bytes, control).map(|bytes| Arc::from(bytes.into_boxed_slice()))
}

fn read_snapshot(
    reader: &mut impl Read,
    max_bytes: u64,
    control: &OperationControl,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        control.check()?;
        let remaining = max_bytes.saturating_sub(bytes.len() as u64);
        // One extra byte proves overflow without reading an unbounded tail.
        let wanted = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
        let read = reader.read(&mut buffer[..wanted]).map_err(|error| {
            Error::new(ErrorKind::MalformedInput).with_context(format!("read input: {error}"))
        })?;
        if read == 0 { break; }
        if read as u64 > remaining {
            return Err(Error::resource_limit(format!("input exceeds the {max_bytes} byte limit")));
        }
        bytes.try_reserve_exact(read)
            .map_err(|error| Error::resource_limit(format!("input allocation: {error}")))?;
        bytes.extend_from_slice(&buffer[..read]);
    }
    control.check()?;
    Ok(bytes)
}

/// Opens an already-owned input snapshot (the raw-bytes host path and tests).
pub(crate) fn open_bytes(
    bytes: Arc<[u8]>,
    limits: &Limits,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
) -> Result<Artifact, Error> {
    control.check()?;
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if len > limits.max_input_bytes {
        return Err(Error::resource_limit(format!(
            "the input snapshot is {len} bytes, above the {} input limit",
            limits.max_input_bytes
        )));
    }
    // Engine-owned budget: the snapshot reserves its full length until the
    // artifact drops (interfaces.md §2: no waiting on another artifact's
    // drop - insufficient budget fails immediately). The reservation is
    // rolled back if the catalog turns out to be malformed.
    reserve_bytes(runtime, len, limits.max_engine_owned_bytes)?;
    match catalog_artifact(bytes, limits, runtime, control) {
        Ok(artifact) => Ok(artifact),
        Err(error) => {
            runtime.active_bytes.fetch_sub(len, Ordering::Relaxed);
            Err(error)
        }
    }
}

/// Assembles the artifact from an already-reserved snapshot: content id,
/// validated catalog and root DEX selection.
fn catalog_artifact(
    bytes: Arc<[u8]>,
    limits: &Limits,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
) -> Result<Artifact, Error> {
    let id = ArtifactId::from_digest(crate::bytes::sha256_controlled(&bytes, control)?);
    let guard = ControlGuard::new(control);
    let catalog = zip::parse_catalog_controlled(&bytes, &limits.input(), &guard.probe())?;
    control.check()?;
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
    Ok(Artifact {
        id,
        bytes,
        catalog: Some(catalog),
        roots,
        runtime: Arc::clone(runtime),
        open_diagnostics,
        limits: *limits,
    })
}

impl Artifact {
    /// Runs `op` over every selected root entry in ordinal order. Each entry
    /// is fully inflated (shared decode budget) and validated before its
    /// operation runs; the first failing entry aborts with its error — rows
    /// computed from earlier entries do not turn that into a success.
    fn fold_roots<T: Send>(
        &self,
        control: &OperationControl,
        measure: impl Fn(&T) -> (usize, usize, u64),
        op: impl Fn(&Root, &container::DexEntryViews<'_>, &ControlProbe<'_>) -> Result<Vec<T>, Error>
            + Sync,
    ) -> Result<(Vec<T>, Vec<Diagnostic>), Error> {
        let guard = ControlGuard::new(control);
        let probe = guard.probe();
        let input_limits = self.limits.input();
        // Deterministic budget reservation: the exact-size decode contract
        // makes the central-directory uncompressed sizes the authoritative
        // output lengths, so the operation's whole decoded-byte budget is
        // decided serially in ordinal order before any parallel work starts.
        // Which entry (if any) crosses the cap therefore never depends on
        // scheduling, and the concurrent decodes hold at most the
        // already-reserved total.
        let mut declared_total: u64 = 0;
        for root in &self.roots {
            if let RootSource::Archive(entry) = &root.source {
                declared_total =
                    declared_total.saturating_add(entry.declared_uncompressed_bytes());
            }
        }
        if declared_total > input_limits.max_total_decoded_bytes {
            return Err(Error::resource_limit(format!(
                "the selected entries declare {declared_total} decoded bytes in total, above the \
                 {} per-operation limit",
                input_limits.max_total_decoded_bytes
            )));
        }
        let decoded = AtomicU64::new(0);
        let mut results = Vec::new();
        let mut integrity = Vec::new();
        let mut used = (0usize, 0usize, 0u64);
        // Bound in-flight result batches by private worker count. Fold in
        // ordinal order so scheduling cannot select a different error.
        for batch in self.roots.chunks(self.runtime.pool.current_num_threads()) {
            #[allow(clippy::type_complexity)]
            let per_root: Vec<Result<(Vec<T>, Vec<Diagnostic>), Error>> =
                self.runtime.pool.install(|| batch.par_iter().map(|root| {
                    let data: &[u8] = match &root.source {
                        RootSource::Archive(entry) => {
                            &zip::read_entry(&self.bytes, entry, &input_limits, &decoded, &probe)?
                        }
                        RootSource::Raw => &self.bytes,
                    };
                    let (views, entry_integrity) = container::validate_dex_entry(
                        self.id, root.ordinal, &root.raw_name, data, &probe,
                    )?;
                    Ok((op(root, &views, &probe)?, entry_integrity))
                }).collect());
            for entry in per_root {
                let (rows, entry_integrity) = entry?;
                for row in rows {
                    probe.check()?;
                    charge_results(&mut used, measure(&row), &self.limits.scan)?;
                    results.push(row);
                }
                integrity.extend(entry_integrity);
            }
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

fn charge_results(
    used: &mut (usize, usize, u64),
    added: (usize, usize, u64),
    limits: &crate::dex::ScanLimits,
) -> Result<(), Error> {
    used.0 = used.0.saturating_add(added.0);
    used.1 = used.1.saturating_add(added.1);
    used.2 = used.2.saturating_add(added.2);
    if used.0 > limits.max_result_items || used.1 > limits.max_result_bytes
        || used.2 > limits.max_reference_locations {
        return Err(Error::resource_limit(format!(
            "operation result uses {} items, {} estimated bytes, {} locations; limits are {}, {}, {}",
            used.0, used.1, used.2, limits.max_result_items, limits.max_result_bytes,
            limits.max_reference_locations,
        )));
    }
    Ok(())
}

fn reference_size(row: &crate::model::Reference) -> (usize, usize, u64) {
    // Same structural coefficients as the scanner, plus variable text storage.
    fn text(value: &DexText) -> usize { value.unit_len().saturating_mul(2) }
    fn prototype(value: &Prototype) -> usize {
        value.parameters().iter().fold(text(value.return_type()), |n, p| n.saturating_add(text(p)))
    }
    use crate::model::TargetValue;
    let caller = row.caller();
    let mut bytes = 320usize.saturating_add(text(caller.owner()))
        .saturating_add(text(caller.name())).saturating_add(prototype(caller.prototype()))
        .saturating_add(caller.dex().raw_entry_name().len());
    let mut locations = 0u64;
    for target in row.targets() {
        let count = target.code_unit_offsets().len();
        locations = locations.saturating_add(count as u64);
        let value_bytes = match target.value() {
            TargetValue::String(t) | TargetValue::Type(t) => text(t),
            TargetValue::Field { owner, name, field_type } => text(owner).saturating_add(text(name)).saturating_add(text(field_type)),
            TargetValue::Method { owner, name, prototype: p } => text(owner).saturating_add(text(name)).saturating_add(prototype(p)),
        };
        bytes = bytes.saturating_add(64).saturating_add(count.saturating_mul(8)).saturating_add(value_bytes);
    }
    (1, bytes, locations)
}

/// The selected logical DEX entries: identity, names, version, header offset.
/// A DEX-less archive yields a successful empty catalog.
fn dexes(artifact: &Artifact, control: &OperationControl) -> Result<Report<Vec<DexEntry>>, Error> {
    let (rows, diagnostics) = artifact.fold_roots(control, |entry: &DexEntry| (1, 128 + entry.raw_entry_name().len(), 0), |_entry, views, _probe| {
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
fn classes(
    artifact: &Artifact,
    filter: &ClassFilter,
    control: &OperationControl,
) -> Result<Report<Vec<Class>>, Error> {
    artifact.require_roots()?;
    let scan_limits = artifact.limits.scan;
    // (class, descriptor) pairs: duplicates are counted across every
    // definition before the filter (a filtered-out duplicate is still a
    // duplicate definition).
    let (pairs, mut diagnostics) = artifact.fold_roots(control, |(class, _): &(Class, String)| {
        if filter.matches(class.java_name()) {
            (1, 320 + class.descriptor().as_str().len() * 8 + class.dex().raw_entry_name().len(), 0)
        } else { (0, 0, 0) }
    }, |_entry, views, probe| {
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
fn references(
    artifact: &Artifact,
    query: &crate::model::ReferenceQuery,
    control: &OperationControl,
) -> Result<Report<Vec<crate::model::Reference>>, Error> {
    artifact.require_roots()?;
    let scan_limits = artifact.limits.scan;
    let (rows, diagnostics) = artifact.fold_roots(control, reference_size, |_entry, views, probe| {
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
fn decompile(
    artifact: &Artifact,
    selector: &ClassSelector,
    control: &OperationControl,
) -> Result<Report<Source>, Error> {
    artifact.require_roots()?;
    struct Resolved {
        entry_index: usize,
        logical: usize,
        class_def_idx: u32,
    }
    if let ClassSelector::Id(id) = selector
        && id.dex().artifact() != artifact.id {
        return Err(Error::invalid_query("class id belongs to a different artifact"));
    }
    if let ClassSelector::Descriptor(_, Some(id)) = selector
        && id.artifact() != artifact.id {
        return Err(Error::invalid_query("DEX id belongs to a different artifact"));
    }
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let decoded = AtomicU64::new(0);
    let mut resolution: Option<Resolved> = None;
    let mut selected_bytes = None;
    let mut definitions = 0usize;
    let mut diagnostics = artifact.open_diagnostics.clone();
    // Visit the entire selected scope, keeping only the chosen entry alive.
    // This both certifies later entries and charges each inflation once.
    for (entry_index, root) in artifact.roots.iter().enumerate() {
        probe.check()?;
        let buffer = match &root.source {
            RootSource::Archive(entry) => Some(zip::read_entry(
                &artifact.bytes, entry, &artifact.limits.input(), &decoded, &probe,
            )?),
            RootSource::Raw => None,
        };
        let data = buffer.as_deref().unwrap_or(&artifact.bytes);
        let (views, integrity) = container::validate_dex_entry(
            artifact.id, root.ordinal, &root.raw_name, data, &probe,
        )?;
        diagnostics.extend(integrity);
        let mut chose_entry = false;
        for (logical, view) in views.views.iter().enumerate() {
            let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
            let hits = match selector {
                ClassSelector::Descriptor(descriptor, pinned) => {
                    if pinned.is_some_and(|id| id != view.id()) { continue; }
                    dex::locate_class(&dex_view, descriptor, &artifact.limits.scan, Some(&probe))?
                }
                ClassSelector::Id(class_id) => {
                    if view.id() != class_id.dex() { continue; }
                    let classes = dex::list_classes(&dex_view, &artifact.limits.scan, Some(&probe))?;
                    if !classes.iter().any(|class| class.id() == *class_id) {
                        return Err(Error::invalid_query("class_def index does not exist"));
                    }
                    vec![class_id.class_def_idx()]
                }
            };
            definitions += hits.len();
            if resolution.is_none()
                && let Some(&class_def_idx) = hits.first() {
                resolution = Some(Resolved { entry_index, logical, class_def_idx });
                chose_entry = true;
            }
        }
        if chose_entry { selected_bytes = buffer; }
    }
    let resolved = resolution.ok_or_else(|| Error::new(ErrorKind::NotFound)
        .with_context("no selected DEX entry defines this class")
        .with_diagnostics(diagnostics.clone()))?;
    if definitions > 1 {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::DuplicateClassDefinition, Severity::Warning, Stage::Dex,
            format!("the descriptor is defined {definitions} times; the first (entry, logical, class_def) identity was decompiled"),
        ));
    }
    let root = &artifact.roots[resolved.entry_index];
    let data = selected_bytes.as_deref().unwrap_or(&artifact.bytes);
    // Recreate borrowed views; integrity diagnostics were collected once above.
    let (views, _) = container::validate_dex_entry(
        artifact.id, root.ordinal, &root.raw_name, data, &probe,
    )?;
    let view = &views.views[resolved.logical];
    // Only integrity findings about *this* view decide whether it needs the
    // normalization scratch; a checksum warning on another entry must not
    // cost a full copy here.
    let view_integrity: Vec<Diagnostic> = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.dex() == Some(view.id()))
        .cloned()
        .collect();
    let scratch = container::backend_scratch(view, &view_integrity);
    let backend_bytes: &[u8] = match &scratch {
        Some(scratch_view) => &scratch_view.bytes,
        None => view.bytes(),
    };
    // The host's cancel flag and deadline are mirrored into the backend
    // token/budget so the backend's own checkpoints honor them, and the
    // budget caps the parse at exactly this view's length.
    let budget = guard.backend_budget(u64::try_from(backend_bytes.len()).unwrap_or(u64::MAX));
    let parsed = droidsaw_dex::analysis::parse_for_analysis(
        backend_bytes,
        &droidsaw_dex::analysis::ParseOptions::default(),
        &budget,
        &guard.backend,
    )
    .map_err(|error| {
        map_backend_error(error).with_context("backend parse")
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
        map_backend_error(error).with_context("backend decompile")
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
fn manifest(
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
        &artifact.limits.manifest,
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

#[cfg(feature = "decompile")]
fn map_backend_error(error: droidsaw_dex::analysis::BackendError) -> Error {
    use crate::error::CancelCause;
    use droidsaw_dex::analysis::BackendError as Backend;
    let kind = match &error {
        Backend::Cancelled => ErrorKind::Cancelled { cause: CancelCause::User },
        Backend::DeadlineExceeded => ErrorKind::Cancelled { cause: CancelCause::Deadline },
        Backend::InputBudget { .. } => ErrorKind::ResourceLimit,
        Backend::InvalidClassDefIndex { .. } => ErrorKind::InvalidQuery,
        Backend::Dex(_) => ErrorKind::MalformedInput,
    };
    Error::new(kind).with_context(error.to_string())
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
                report
                    .typed_elements
                    .iter()
                    .map(|(name, value)| {
                        (DexText::from_str_lossless(name), typed_to_encoded(value))
                    })
                    .collect(),
                render_annotation_elements(&report.elements),
            ),
        })
        .collect();
    let fields = metadata
        .static_fields
        .iter()
        .map(|report| FieldMetadata {
            name: DexText::from_str_lossless(&report.name),
            field_type: DexText::from_str_lossless(&report.type_descriptor),
            access_flags: report.access_flags,
            generic_signature: None,
            initial_value: report.typed_value.as_ref().map(typed_to_encoded),
        })
        .chain(
        metadata
        .instance_field_reports
        .iter()
        .map(|report| FieldMetadata {
            name: DexText::from_str_lossless(&report.name),
            field_type: DexText::from_str_lossless(&report.type_descriptor),
            access_flags: report.access_flags,
            generic_signature: None,
            initial_value: None,
        })
        )
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
/// Maps the backend's resolved typed record onto the frozen model value.
/// Floats/doubles arrive as raw IEEE-754 bits, so no textual rounding can
/// change a constant (DECL-01).
fn typed_to_encoded(value: &droidsaw_dex::analysis::TypedValue) -> crate::model::EncodedValue {
    use crate::model::EncodedValue as M;
    use droidsaw_dex::analysis::TypedValue as T;
    match value {
        T::Null => M::Null,
        T::Boolean(b) => M::Boolean(*b),
        T::Byte(n) => M::Byte(*n),
        T::Short(n) => M::Short(*n),
        T::Int(n) => M::Int(*n),
        T::Long(n) => M::Long(*n),
        T::Char(c) => M::Char(*c),
        T::FloatBits(bits) => M::Float(*bits),
        T::DoubleBits(bits) => M::Double(*bits),
        T::Text(text) => M::String(DexText::from_str_lossless(text)),
        T::Type(desc) => M::Type(DexText::from_str_lossless(desc)),
        T::Field { class, name, ty } => M::Field {
            owner: DexText::from_str_lossless(class),
            name: DexText::from_str_lossless(name),
            field_type: DexText::from_str_lossless(ty),
        },
        T::Method { class, name, proto } => M::Method {
            owner: DexText::from_str_lossless(class),
            name: DexText::from_str_lossless(name),
            prototype: prototype_from_descriptor(proto),
        },
        T::Enum { class, name } => M::Enum {
            owner: DexText::from_str_lossless(class),
            name: DexText::from_str_lossless(name),
        },
        T::Array(items) => M::Array(items.iter().map(typed_to_encoded).collect()),
        T::Annotation { type_descriptor, elements } => M::Annotation(crate::model::AnnotationRecord {
            visibility: crate::model::AnnotationVisibility::Runtime,
            type_descriptor: DexText::from_str_lossless(type_descriptor),
            items: elements
                .iter()
                .map(|(name, value)| {
                    (DexText::from_str_lossless(name), typed_to_encoded(value))
                })
                .collect(),
            rendered: render_annotation_elements(&elements
                .iter()
                .map(|(n, v)| (n.clone(), format!("{v:?}")))
                .collect::<Vec<_>>()),
        }),
        T::MethodType(text) => M::Type(DexText::from_str_lossless(text)),
        // The model has no method-handle variant; the exact u32 index rides
        // in a Long instead of a sign-truncating Int (a handle index at or
        // above 2^31 must not wrap negative).
        T::MethodHandle(index) => M::Long(i64::from(*index)),
    }
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

#[cfg(feature = "decompile")]
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
        let consumed = prototype_component_size(rest);
        parameters.push(DexText::from_str_lossless(&rest[..consumed]));
        rest = &rest[consumed..];
    }
    Prototype::new(parameters, DexText::from_str_lossless(ret))
}

/// Length of one parameter type at the head of `rest`: 1 per primitive unit,
/// up to and including the `;` for class types, and 1 per array dimension
/// plus its component (nested arrays are one parameter, so `[[I` consumes
/// all three units).
#[cfg(feature = "decompile")]
fn prototype_component_size(rest: &str) -> usize {
    match rest.as_bytes().first() {
        Some(b'[') => 1 + prototype_component_size(&rest[1..]),
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

    #[test]
    fn snapshot_stops_at_the_first_byte_above_the_actual_limit() {
        let mut growing = std::io::Cursor::new(vec![0u8; 128 * 1024]);
        let error = read_snapshot(&mut growing, 17, &no_control()).unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::ResourceLimit);
        assert_eq!(growing.position(), 18, "do not read or retain the unbounded tail");
        let small = read_snapshot(&mut std::io::Cursor::new(b"ok"), 2, &no_control()).unwrap();
        assert_eq!(small, b"ok");
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn backend_control_shares_live_cancellation_and_preserves_causes() {
        use droidsaw_dex::analysis::BackendError;
        use crate::error::CancelCause;
        let flag = Arc::new(AtomicBool::new(false));
        let control = OperationControl::new().with_cancel_flag(Arc::clone(&flag));
        let guard = ControlGuard::new(&control);
        assert!(!guard.backend.is_cancelled());
        flag.store(true, Ordering::Release);
        assert!(guard.backend.is_cancelled());
        assert_eq!(map_backend_error(BackendError::Cancelled).kind(),
            &ErrorKind::Cancelled { cause: CancelCause::User });
        assert_eq!(map_backend_error(BackendError::DeadlineExceeded).kind(),
            &ErrorKind::Cancelled { cause: CancelCause::Deadline });
        assert_eq!(map_backend_error(BackendError::InputBudget { bytes: 2, cap: 1 }).kind(),
            &ErrorKind::ResourceLimit);
    }

    /// A fresh engine runtime for tests (each call = its own account).
    fn test_runtime() -> Arc<Runtime> {
        Engine::new(EngineOptions::default()).unwrap().runtime
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
        // A one-entry query must not charge the selected DEX twice.
        let limits = Limits { max_total_decoded_bytes: dex.len() as u64, ..Limits::default() };
        let artifact = open_path(&path, &limits, &test_runtime(), &no_control()).unwrap();
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

    #[cfg(feature = "manifest")]
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

    #[cfg(feature = "decompile")]
    #[test]
    fn prototype_descriptor_splits_nested_array_parameters() {
        let proto = prototype_from_descriptor("([[Ljava/lang/String;[II)Z");
        let params: Vec<String> = proto
            .parameters()
            .iter()
            .map(|text| text.as_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(params, ["[[Ljava/lang/String;", "[I", "I"], "{params:?}");
        assert_eq!(proto.return_type().as_str().unwrap_or_default(), "Z");

        // Single-dimension arrays and plain class types keep parsing as one
        // parameter each.
        let proto = prototype_from_descriptor("([Ljava/lang/Object;J)V");
        let params: Vec<String> = proto
            .parameters()
            .iter()
            .map(|text| text.as_str().unwrap_or_default().to_owned())
            .collect();
        assert_eq!(params, ["[Ljava/lang/Object;", "J"], "{params:?}");
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

/// Engine construction options.
#[derive(Clone, Copy, Debug, Default)]
pub struct EngineOptions {
    pub limits: Limits,
    /// Private worker count. `None` selects one worker; `Some(0)` is rejected.
    pub threads: Option<usize>,
}

/// Shared engine runtime: serial top-level admission, the engine-owned
/// active-bytes account and the worker pool. Clones share one runtime
/// (interfaces.md §2: the Engine is a cloneable handle over one private
/// runtime).
#[derive(Debug)]
pub(crate) struct Runtime {
    /// Serial top-level admission: held for the duration of one operation.
    /// Waiters use a bounded lock poll so a cancelled or
    /// deadline-expired host never queues forever (interfaces.md §5).
    admission: Mutex<()>,
    /// Retained input bytes (catalog/working allocations are tracked separately
    /// in the embedding audit debt). Inputs are opened
    /// through this engine and released with the artifact.
    active_bytes: AtomicU64,
    /// Every parallel analysis stage, including vendor parsing, uses this pool.
    pool: Arc<rayon::ThreadPool>,
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
        let count = options.threads.unwrap_or(1);
        if count == 0 {
            return Err(Error::invalid_query("worker threads must be greater than zero"));
        }
        let pool = Arc::new(rayon::ThreadPoolBuilder::new()
            .num_threads(count)
            .build()
            .map_err(|error| Error::invalid_query(format!("worker pool: {error}")))?);
        let runtime = Arc::new(Runtime {
            admission: Mutex::new(()),
            active_bytes: AtomicU64::new(0),
            pool,
        });
        Ok(Engine { options, runtime })
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
            InputKind::Dex => {
                open_dex_bytes(bytes, &self.options.limits, &self.runtime, control)
            }
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
        self.runtime.pool.install(|| decompile(artifact, selector, control))
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
    let bytes = read_path_snapshot(path, limits.max_input_bytes, control)?;
    open_dex_bytes(bytes, limits, runtime, control)
}

/// Opens an owned raw DEX byte stream: entry ordinal 0, display name
/// `<memory.dex>` (interfaces.md §1). The same input/engine-byte limits as
/// the APK path apply, and the artifact carries the engine's configured
/// operation limits (not silently the defaults).
fn open_dex_bytes(
    bytes: Arc<[u8]>,
    limits: &Limits,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
) -> Result<Artifact, Error> {
    control.check()?;
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if len > limits.max_input_bytes {
        return Err(Error::resource_limit(format!(
            "the raw DEX input is {len} bytes, above the {} input limit",
            limits.max_input_bytes
        )));
    }
    let id = ArtifactId::from_digest(crate::bytes::sha256_controlled(&bytes, control)?);
    reserve_bytes(runtime, len, limits.max_engine_owned_bytes)?;
    let roots = vec![Root { ordinal: 0, raw_name: b"<memory.dex>".to_vec(), source: RootSource::Raw }];
    let artifact = Artifact {
        id,
        bytes,
        catalog: None,
        roots,
        runtime: Arc::clone(runtime),
        open_diagnostics: Vec::new(),
        limits: *limits,
    };
    Ok(artifact)
}
