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
use crate::bytes::OperationControl;
use crate::dex::container;
#[cfg(feature = "decompile")]
use crate::dex::container::ValidatedDexView;
use crate::dex::{self, ScanOptions};
use crate::error::{Error, ErrorKind};
#[cfg(feature = "decompile")]
use crate::model::{
    AnnotationEntry, AnnotationRecord, AnnotationTarget, AnnotationVisibility, ArtifactId, Class,
    ClassDescriptor, ClassFilter, ClassId, ClassMetadata, ClassSelector, DexText,
    Diagnostic, DiagnosticCode, EncodedValue, EnclosingRecord, FieldDeclaration, FieldId,
    FieldMetadata, InnerClassRecord, MethodDeclaration, MethodIdentity, MethodInventory,
    MethodMetadata, MethodTarget, OperationStats, Prototype, Report, Severity, Source,
    SourceMetadata, Stage,
};
use crate::model::{
    ArchiveEntry as ArchiveEntryFact, ArchiveEntryId, ArchiveEntryQuery, MethodScope,
    DexEntry, InstructionFact, MemoryPermit, MethodId, StringDeclaration,
    ClassRelation, ClassRelationQuery, TargetId, TargetKind,
};
use crate::memory::MemoryAccount;
#[cfg(not(feature = "decompile"))]
use crate::model::{
    ArtifactId, Class, ClassFilter, DexText, Diagnostic, DiagnosticCode, OperationStats,
    Prototype, Report, Severity, Stage,
};
use crate::zip::{self, ArchiveEntry as ZipArchiveEntry};
use rayon::prelude::*;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64};
#[cfg(test)]
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

/// Per-open and per-operation resource limits the CLI can override
/// (interfaces.md §5 keys enforced by this layer). Unlisted keys (logical
/// dex count, code units) keep their internal defaults.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// `input-bytes`: the owned snapshot may not exceed this.
    pub max_input_bytes: u64,
    /// Shared ledger limit for live input, decoded buffers, scan/parser/pipeline
    /// working estimates and retained reports. This is not a process RSS cap;
    /// allocator bookkeeping and caller-owned copies are outside the ledger.
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
            Some(flag) => ControlProbe {
                cancelled: flag,
                deadline: self.deadline,
            },
            None => ControlProbe {
                cancelled: &self.dummy,
                deadline: self.deadline,
            },
        }
    }

    /// The backend budget derived from the host control: the same deadline,
    /// plus an input-length cap for the bytes being parsed.
    #[cfg(feature = "decompile")]
    fn backend_budget(&self, input_len: u64, artifact: &Artifact) -> droidsaw_dex::analysis::Budget {
        droidsaw_dex::analysis::Budget {
            deadline: self.deadline,
            max_input_bytes: Some(input_len),
            memory: Some(artifact.runtime.memory.clone()),
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
    Archive(ZipArchiveEntry),
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
    /// Charges the immutable input snapshot for the artifact lifetime.
    #[allow(dead_code)]
    input_memory: MemoryPermit,
    /// Charges the retained archive catalog and root projection.
    #[allow(dead_code)]
    catalog_memory: Option<MemoryPermit>,
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

    #[cfg(test)]
    fn byte_len(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

}

/// Atomically reserves `len` bytes against the engine-owned budget. The
/// check and the add are one CAS loop, so concurrent opens cannot both pass
/// the same headroom the way a load-compare-then-add sequence allowed.
fn reserve_bytes(
    runtime: &Runtime,
    len: u64,
    max: u64,
    label: &str,
) -> Result<MemoryPermit, Error> {
    runtime.memory.reserve_with_limit(len, max, label)
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
    let mut file = File::open(path).map_err(|error| {
        Error::new(ErrorKind::NotFound).with_context(format!("open {path:?}: {error}"))
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::new(ErrorKind::NotFound).with_context(format!("stat {path:?}: {error}"))
    })?;
    if !metadata.is_file() {
        return Err(Error::new(ErrorKind::UnsupportedFormat)
            .with_context(format!("{path:?} is not a regular file")));
    }
    if metadata.len() > max_bytes {
        return Err(Error::resource_limit(format!(
            "{path:?} exceeds the {max_bytes} input limit"
        )));
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
        if read == 0 {
            break;
        }
        if read as u64 > remaining {
            return Err(Error::resource_limit(format!(
                "input exceeds the {max_bytes} byte limit"
            )));
        }
        bytes
            .try_reserve_exact(read)
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
    let input_memory = reserve_bytes(runtime, len, limits.max_engine_owned_bytes, "input snapshot")?;
    match catalog_artifact(bytes, limits, runtime, control, input_memory) {
        Ok(artifact) => Ok(artifact),
        Err(error) => Err(error),
    }
}

/// Assembles the artifact from an already-reserved snapshot: content id,
/// validated catalog and root DEX selection.
fn catalog_artifact(
    bytes: Arc<[u8]>,
    limits: &Limits,
    runtime: &Arc<Runtime>,
    control: &OperationControl,
    input_memory: MemoryPermit,
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
    let roots: Vec<Root> = selection
        .selected
        .into_iter()
        .map(|entry| Root {
            ordinal: entry.ordinal,
            raw_name: entry.raw_name.clone(),
            source: RootSource::Archive(entry.clone()),
        })
        .collect();
    let catalog_bytes = catalog.estimated_bytes().saturating_add(
        roots
            .iter()
            .map(|root| root.raw_name.len() as u64)
            .sum::<u64>(),
    );
    let catalog_memory = runtime
        .memory
        .reserve_with_limit(catalog_bytes, limits.max_engine_owned_bytes, "archive catalog")?;
    Ok(Artifact {
        id,
        bytes,
        catalog: Some(catalog),
        roots,
        runtime: Arc::clone(runtime),
        input_memory,
        catalog_memory: Some(catalog_memory),
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
    ) -> Result<(Vec<T>, Vec<Diagnostic>, Vec<MemoryPermit>), Error> {
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
                declared_total = declared_total.saturating_add(entry.declared_uncompressed_bytes());
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
        // Keep the scan estimate alive while rows produced by that scan are
        // being folded and until the final report reservation succeeds.
        // This closes the batch window in which rows outlived their scratch
        // permit without charging the whole result limit up front.
        let mut work_memory = Vec::new();
        let mut used = (0usize, 0usize, 0u64);
        // Bound in-flight result batches by private worker count. Fold in
        // ordinal order so scheduling cannot select a different error.
        for batch in self.roots.chunks(self.runtime.pool.current_num_threads()) {
            let mut decode_permits = Vec::with_capacity(batch.len());
            for root in batch {
                decode_permits.push(match &root.source {
                    RootSource::Archive(entry) => Some(self.runtime.memory.reserve_with_limit(
                        entry.declared_uncompressed_bytes(),
                        self.limits.max_engine_owned_bytes,
                        "decoded DEX entry",
                    )?),
                    RootSource::Raw => None,
                });
            }
            #[allow(clippy::type_complexity)]
            let per_root: Vec<Result<(Vec<T>, Vec<Diagnostic>, MemoryPermit), Error>> =
                self.runtime.pool.install(|| {
                    batch
                        .par_iter()
                        .zip(decode_permits.into_par_iter())
                        .map(|(root, _decode_permit)| {
                            let data: &[u8] = match &root.source {
                                RootSource::Archive(entry) => &zip::read_entry(
                                    &self.bytes,
                                    entry,
                                    &input_limits,
                                    &decoded,
                                    &probe,
                                )?,
                                RootSource::Raw => &self.bytes,
                            };
                            let (views, entry_integrity) = container::validate_dex_entry(
                                self.id,
                                root.ordinal,
                                &root.raw_name,
                                data,
                                &probe,
                            )?;
                            let work_bytes = views
                                .views
                                .iter()
                                .enumerate()
                                .map(|(logical, view)| {
                                    let dex_view =
                                        dex::DexView::new(views.dex_entry(logical), view.bytes());
                                    dex::estimated_scan_work(&dex_view, &self.limits.scan)
                                })
                                .try_fold(0u64, |total, estimate| {
                                    total.checked_add(estimate?).ok_or_else(||
                                        Error::resource_limit("logical DEX working-set sum overflow"))
                                })?;
                            let scan_memory = self.runtime.memory.reserve_with_limit(
                                work_bytes,
                                self.limits.max_engine_owned_bytes,
                                "DEX scan working set",
                            )?;
                            let rows = op(root, &views, &probe)?;
                            Ok((rows, entry_integrity, scan_memory))
                        })
                        .collect()
                });
            for entry in per_root {
                let (rows, entry_integrity, scan_memory) = entry?;
                work_memory.push(scan_memory);
                for row in rows {
                    probe.check()?;
                    charge_results(&mut used, measure(&row), &self.limits.scan)?;
                    results.push(row);
                }
                integrity.extend(entry_integrity);
            }
        }
        let diagnostics = self
            .open_diagnostics
            .iter()
            .cloned()
            .chain(integrity.iter().cloned())
            .collect();
        Ok((results, diagnostics, work_memory))
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
    if used.0 > limits.max_result_items
        || used.1 > limits.max_result_bytes
        || used.2 > limits.max_reference_locations
    {
        return Err(Error::resource_limit(format!(
            "operation result uses {} items, {} estimated bytes, {} locations; limits are {}, {}, {}",
            used.0,
            used.1,
            used.2,
            limits.max_result_items,
            limits.max_result_bytes,
            limits.max_reference_locations,
        )));
    }
    Ok(())
}

fn reserve_report_memory(
    artifact: &Artifact,
    result_bytes: usize,
    diagnostics: &[Diagnostic],
    label: &str,
) -> Result<MemoryPermit, Error> {
    if result_bytes > artifact.limits.scan.max_result_bytes {
        return Err(Error::resource_limit(format!(
            "{label} payload uses {result_bytes} bytes, above the {} result limit",
            artifact.limits.scan.max_result_bytes
        )));
    }
    let result_bytes = u64::try_from(result_bytes).unwrap_or(u64::MAX);
    let diagnostic_bytes = diagnostics.iter().fold(0u64, |total, diagnostic| {
        total
            .saturating_add(96)
            .saturating_add(diagnostic.message().len() as u64)
    });
    let total = result_bytes.checked_add(diagnostic_bytes).ok_or_else(|| {
        Error::resource_limit(format!("{label} allocation size overflows the account"))
    })?;
    artifact
        .runtime
        .memory
        .reserve_with_limit(total, artifact.limits.max_engine_owned_bytes, label)
}

fn reference_size(row: &crate::model::Reference) -> (usize, usize, u64) {
    // Same structural coefficients as the scanner, plus variable text storage.
    fn text(value: &DexText) -> usize {
        value.unit_len().saturating_mul(2)
    }
    fn prototype(value: &Prototype) -> usize {
        value
            .parameters()
            .iter()
            .fold(text(value.return_type()), |n, p| n.saturating_add(text(p)))
    }
    use crate::model::TargetValue;
    let caller = row.caller();
    let mut bytes = 320usize
        .saturating_add(text(caller.owner()))
        .saturating_add(text(caller.name()))
        .saturating_add(prototype(caller.prototype()))
        .saturating_add(caller.dex().raw_entry_name().len());
    let mut locations = 0u64;
    for target in row.targets() {
        let count = target.code_unit_offsets().len();
        locations = locations.saturating_add(count as u64);
        let value_bytes = match target.value() {
            TargetValue::String(t) | TargetValue::Type(t) => text(t),
            TargetValue::Field {
                owner,
                name,
                field_type,
            } => text(owner)
                .saturating_add(text(name))
                .saturating_add(text(field_type)),
            TargetValue::Method {
                owner,
                name,
                prototype: p,
            } => text(owner)
                .saturating_add(text(name))
                .saturating_add(prototype(p)),
        };
        bytes = bytes
            .saturating_add(64)
            .saturating_add(count.saturating_mul(8))
            .saturating_add(value_bytes);
    }
    (1, bytes, locations)
}

/// The selected logical DEX entries: identity, names, version, header offset.
/// A DEX-less archive yields a successful empty catalog.
fn dexes(artifact: &Artifact, control: &OperationControl) -> Result<Report<Vec<DexEntry>>, Error> {
    let (rows, diagnostics, work_memory) = artifact.fold_roots(
        control,
        |entry: &DexEntry| (1, 128usize.saturating_add(entry.raw_entry_name().len()), 0),
        |_entry, views, _probe| {
            let mut rows = Vec::with_capacity(views.views.len());
            for logical in 0..views.views.len() {
                rows.push(views.dex_entry(logical));
            }
            Ok(rows)
        },
    )?;
    let stats = OperationStats {
        selected_dexes: rows.len() as u32,
        ..Default::default()
    };
    let bytes = rows
        .iter()
        .map(|entry| 128usize.saturating_add(entry.raw_entry_name().len()))
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, bytes, &diagnostics, "DEX report")?;
    drop(work_memory);
    Ok(Report::new(rows, diagnostics, stats).with_memory(memory))
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
    let (pairs, mut diagnostics, work_memory) = artifact.fold_roots(
        control,
        |(class, _): &(Class, String)| {
            if filter.matches(class.java_name()) {
                (
                    1,
                    320 + class.descriptor().as_str().len() * 8
                        + class.dex().raw_entry_name().len(),
                    0,
                )
            } else {
                (0, 0, 0)
            }
        },
        |_entry, views, probe| {
            let mut pairs = Vec::new();
            for (logical, view) in views.views.iter().enumerate() {
                let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
                for class in dex::list_classes(&dex_view, &scan_limits, Some(probe))? {
                    let descriptor = class.descriptor().as_str().to_owned();
                    pairs.push((class, descriptor));
                }
            }
            Ok(pairs)
        },
    )?;
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
    let stats = OperationStats {
        result_items: rows.len() as u64,
        ..Default::default()
    };
    let bytes = rows
        .iter()
        .map(|class| {
            320usize
                .saturating_add(class.descriptor().as_str().len().saturating_mul(8))
                .saturating_add(class.dex().raw_entry_name().len())
        })
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, bytes, &diagnostics, "class report")?;
    drop(work_memory);
    Ok(Report::new(rows, diagnostics, stats).with_memory(memory))
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
    let (rows, diagnostics, work_memory) =
        artifact.fold_roots(control, reference_size, |_entry, views, probe| {
            let mut rows = Vec::new();
            for (logical, view) in views.views.iter().enumerate() {
                let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
                let options = ScanOptions {
                    limits: scan_limits,
                    control: Some(probe),
                    prefilter: true,
                };
                rows.extend(dex::scan_references(&dex_view, query, &options)?);
            }
            Ok(rows)
        })?;
    let stats = OperationStats {
        result_items: rows.len() as u64,
        matched_targets: rows.iter().map(|row| row.targets().len() as u64).sum(),
        ..Default::default()
    };
    let bytes = rows
        .iter()
        .map(reference_size)
        .map(|(_, bytes, _)| bytes)
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, bytes, &diagnostics, "reference report")?;
    drop(work_memory);
    Ok(Report::new(rows, diagnostics, stats).with_memory(memory))
}

fn classes_in_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    filter: &ClassFilter,
    control: &OperationControl,
) -> Result<Report<Vec<Class>>, Error> {
    let scan_limits = artifact.limits.scan;
    let (pairs, mut diagnostics, work_memory) = fold_scope(
        artifact,
        scope,
        control,
        |(class, _): &(Class, String)| {
            if filter.matches(class.java_name()) {
                (
                    1,
                    320 + class.descriptor().as_str().len() * 8
                        + class.dex().raw_entry_name().len(),
                    0,
                )
            } else {
                (0, 0, 0)
            }
        },
        |views, logical, probe| {
            let view = &views.views[logical];
            let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
            let classes = dex::list_classes(&dex_view, &scan_limits, Some(probe))?;
            Ok(classes
                .into_iter()
                .map(|class| {
                    let descriptor = class.descriptor().as_str().to_owned();
                    (class, descriptor)
                })
                .collect())
        },
    )?;
    let mut descriptor_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut rows = Vec::new();
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
                    "descriptor {descriptor} is defined {count} times; identity is the (entry, logical, class_def) index"
                ),
            ));
        }
    }
    rows.sort_by_key(Class::id);
    let result_items = rows.len() as u64;
    let bytes = rows
        .iter()
        .map(|class| {
            320usize
                .saturating_add(class.descriptor().as_str().len().saturating_mul(8))
                .saturating_add(class.dex().raw_entry_name().len())
        })
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, bytes, &diagnostics, "scoped class report")?;
    drop(work_memory);
    Ok(Report::new(
        rows,
        diagnostics,
        OperationStats {
            result_items,
            ..Default::default()
        },
    )
    .with_memory(memory))
}

/// Conservative owned-result bound including deep Class/DexEntry copies,
/// vector growth and per-source de-duplication tree nodes. Temporary decoded
/// strings are covered separately, before the scanner is entered.
fn class_relation_bytes(
    descriptor: &crate::model::ClassDescriptor,
    entry: &DexEntry,
    target: &DexText,
) -> usize {
    // During fold_scope source and destination vectors coexist, each with
    // nearly 2x len capacity. Payloads move, but four struct slots stay live.
    let slots = std::mem::size_of::<ClassRelation>()
        .saturating_add(std::mem::size_of::<MemoryPermit>())
        .saturating_mul(4);
    64usize
        .saturating_add(descriptor.as_str().len().saturating_mul(12))
        .saturating_add(entry.raw_entry_name().len())
        .saturating_add(entry.display_name().unit_len().saturating_mul(2))
        .saturating_add(entry.logical_name().unit_len().saturating_mul(2))
        .saturating_add(target.unit_len().saturating_mul(2))
        .saturating_mul(2)
        .saturating_add(slots)
}

fn class_relations_in_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    query: &ClassRelationQuery,
    control: &OperationControl,
) -> Result<Report<Vec<ClassRelation>>, Error> {
    let limits = artifact.limits.scan;
    // A callback shares this counter across every selected logical DEX. Limits
    // are checked before allocation rather than only after a DEX has finished.
    let mut used = (0usize, 0usize, 0u64);
    let (accounted, diagnostics, work_memory) = fold_scope(
        artifact,
        scope,
        control,
        |(row, _): &(ClassRelation, MemoryPermit)| {
            (
                1,
                class_relation_bytes(row.class().descriptor(), row.class().dex(), row.target()),
                0,
            )
        },
        |views, logical, probe| {
            let entry = views.dex_entry(logical);
            let view = &views.views[logical];
            let dex_view = dex::DexView::new(entry.clone(), view.bytes());
            // Two decoded strings plus source projections are simultaneously
            // live. MUTF-8 uses >=1 byte per UTF-16 unit, and decoding also
            // honors max_string_units. 16x the smaller bound safely covers
            // Vec growth and Unicode conversion, including
            // aliased pool strings, without allocating a pool-sized cache.
            let _text_memory = artifact.runtime.memory.reserve_with_limit(
                (view.bytes().len().min(limits.max_string_units) as u64)
                    .saturating_mul(16)
                    // Eight metadata intervals per validated member; doubled
                    // capacity covers growth of the exclusion vector.
                    .saturating_add((views.views.len() as u64).saturating_mul(256)),
                artifact.limits.max_engine_owned_bytes,
                "class relationship decode scratch",
            )?;
            let mut rows = Vec::new();
            dex::scan_class_relations(
                &dex_view,
                query,
                &limits,
                Some(probe),
                |class_index, descriptor, target_index, target| {
                    let bytes = class_relation_bytes(descriptor, &entry, target);
                    charge_results(&mut used, (1, bytes, 0), &limits)?;
                    let memory = artifact.runtime.memory.reserve_with_limit(
                        bytes as u64,
                        artifact.limits.max_engine_owned_bytes,
                        "class relationship row",
                    )?;
                    let class = Class::new(
                        crate::model::ClassId::new(entry.id(), class_index),
                        entry.clone(),
                        descriptor.clone(),
                    );
                    rows.push((
                        ClassRelation::new(
                            class,
                            query.kind(),
                            TargetId::new(entry.id(), TargetKind::Type, target_index),
                            target.clone(),
                        ),
                        memory,
                    ));
                    Ok(())
                },
            )?;
            Ok(rows)
        },
    )?;
    let memory =
        reserve_report_memory(artifact, used.1, &diagnostics, "class relationship report")?;
    // All row permits remain alive while the final vector allocates. Its full
    // charge is already reserved by the report permit above.
    let mut rows = Vec::with_capacity(accounted.len());
    for (row, _row_memory) in accounted {
        rows.push(row);
    }
    rows.sort_by_key(|row| (row.class().id(), row.target_id().table_index()));
    drop(work_memory);
    let result_items = rows.len() as u64;
    Ok(Report::new(
        rows,
        diagnostics,
        OperationStats {
            result_items,
            matched_targets: result_items,
            ..Default::default()
        },
    )
    .with_memory(memory))
}

fn references_in_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    query: &crate::model::ReferenceQuery,
    control: &OperationControl,
) -> Result<Report<Vec<crate::model::Reference>>, Error> {
    let scan_limits = artifact.limits.scan;
    let (rows, diagnostics, work_memory) = fold_scope(
        artifact,
        scope,
        control,
        reference_size,
        |views, logical, probe| {
            let view = &views.views[logical];
            let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
            let options = ScanOptions {
                limits: scan_limits,
                control: Some(probe),
                prefilter: true,
            };
            dex::scan_references(&dex_view, query, &options)
        },
    )?;
    let bytes = rows
        .iter()
        .map(reference_size)
        .map(|(_, bytes, _)| bytes)
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, bytes, &diagnostics, "scoped reference report")?;
    drop(work_memory);
    Ok(Report::new(
        rows.clone(),
        diagnostics,
        OperationStats {
            result_items: rows.len() as u64,
            matched_targets: rows.iter().map(|row| row.targets().len() as u64).sum(),
            ..Default::default()
        },
    )
    .with_memory(memory))
}

fn strings_in_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
) -> Result<Report<Vec<StringDeclaration>>, Error> {
    let scan_limits = artifact.limits.scan;
    let (rows, diagnostics, work_memory) = fold_scope(
        artifact,
        scope,
        control,
        |row: &StringDeclaration| {
            (
                1,
                160usize.saturating_add(row.value().unit_len().saturating_mul(2)),
                0,
            )
        },
        |views, logical, probe| {
            let entry = views.dex_entry(logical);
            let view = &views.views[logical];
            let dex_view = dex::DexView::new(entry.clone(), view.bytes());
            Ok(dex::list_strings(&dex_view, &scan_limits, Some(probe))?
                .into_iter()
                .map(|(index, value)| StringDeclaration::new(entry.clone(), index, value))
                .collect())
        },
    )?;
    let memory_bytes = rows
        .iter()
        .map(|row| 160usize.saturating_add(row.value().unit_len().saturating_mul(2)))
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, memory_bytes, &diagnostics, "string inventory report")?;
    drop(work_memory);
    Ok(Report::new(
        rows.clone(),
        diagnostics,
        OperationStats {
            selected_dexes: rows.iter().map(|row| row.dex().id()).collect::<std::collections::BTreeSet<_>>().len() as u32,
            result_items: rows.len() as u64,
            ..Default::default()
        },
    )
    .with_memory(memory))
}

fn instruction_fact_size(row: &InstructionFact) -> (usize, usize, u64) {
    let identity_bytes = row.method_target().map_or(0usize, |identity| {
        let prototype = identity
            .prototype()
            .parameters()
            .iter()
            .map(|parameter| parameter.unit_len().saturating_mul(2))
            .fold(identity.prototype().return_type().unit_len().saturating_mul(2), usize::saturating_add);
        identity
            .owner()
            .unit_len()
            .saturating_add(identity.name().unit_len())
            .saturating_mul(2)
            .saturating_add(prototype)
    });
    let bytes = 128usize
        .saturating_add(identity_bytes)
        .saturating_add(4)
        .saturating_add(row.reads().len().saturating_mul(2))
        .saturating_add(row.writes().len().saturating_mul(2))
        .saturating_add(row.branch_targets().len().saturating_mul(4));
    (1, bytes, 0)
}

/// Typed instruction facts over an explicit DEX scope.  The provider validates
/// instruction widths and bounds with the same scanner walk used by reference
/// queries, while exposing only bounded operands and no borrowed input bytes.
pub(crate) fn instructions_in_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
) -> Result<Report<Vec<InstructionFact>>, Error> {
    instructions_in_scope_filtered(artifact, scope, control, None)
}

/// Typed instruction facts for a bounded set of method identities.  Scope
/// validation and archive integrity still cover the selected DEX entries, but
/// code items outside `methods` are not decoded or retained in the report.
pub(crate) fn instructions_for_methods_in_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    methods: &[MethodId],
    control: &OperationControl,
) -> Result<Report<Vec<InstructionFact>>, Error> {
    let mut by_dex = std::collections::BTreeMap::new();
    for method in methods {
        by_dex
            .entry(method.dex())
            .or_insert_with(std::collections::BTreeSet::new)
            .insert(method.method_idx());
    }
    instructions_in_scope_filtered(artifact, scope, control, Some(&by_dex))
}

fn instructions_in_scope_filtered(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
    method_filter: Option<&std::collections::BTreeMap<crate::model::DexId, std::collections::BTreeSet<u32>>>,
) -> Result<Report<Vec<InstructionFact>>, Error> {
    let scan_limits = artifact.limits.scan;
    let (rows, diagnostics, work_memory) = fold_scope(
        artifact,
        scope,
        control,
        instruction_fact_size,
        |views, logical, probe| {
            let view = &views.views[logical];
            let entry = views.dex_entry(logical);
            let selected = method_filter.and_then(|filter| filter.get(&entry.id()));
            if method_filter.is_some() && selected.is_none() {
                return Ok(Vec::new());
            }
            let dex_view = dex::DexView::new(entry, view.bytes());
            match method_filter {
                None => dex::list_instructions(&dex_view, &scan_limits, Some(probe)),
                Some(_) => dex::list_instructions_for_methods(
                    &dex_view,
                    &scan_limits,
                    Some(probe),
                    selected,
                ),
            }
        },
    )?;
    let bytes = rows
        .iter()
        .map(instruction_fact_size)
        .map(|(_, bytes, _)| bytes)
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, bytes, &diagnostics, "instruction fact report")?;
    drop(work_memory);
    Ok(Report::new(
        rows.clone(),
        diagnostics,
        OperationStats {
            selected_dexes: rows
                .iter()
                .map(|row| row.dex().id())
                .collect::<std::collections::BTreeSet<_>>()
                .len() as u32,
            result_items: rows.len() as u64,
            ..Default::default()
        },
    )
    .with_memory(memory))
}

/// Resolves an explicit method scope to logical DEX identities without
/// building class or method inventories. Entry bytes and DEX structure are
/// still checked through the same scoped validation pipeline.
fn dexes_in_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
) -> Result<Report<Vec<DexEntry>>, Error> {
    let (rows, diagnostics, work_memory) = fold_scope(
        artifact,
        scope,
        control,
        |entry: &DexEntry| (1, 128 + entry.raw_entry_name().len(), 0),
        |views, logical, _probe| Ok(vec![views.dex_entry(logical)]),
    )?;
    let selected_dexes = rows.len() as u32;
    let result_items = rows.len() as u64;
    let bytes = rows
        .iter()
        .map(|entry| 128usize.saturating_add(entry.raw_entry_name().len()))
        .fold(0usize, usize::saturating_add);
    let memory = reserve_report_memory(artifact, bytes, &diagnostics, "scoped DEX report")?;
    drop(work_memory);
    Ok(Report::new(
        rows,
        diagnostics,
        OperationStats {
            selected_dexes,
            result_items,
            ..Default::default()
        },
    )
    .with_memory(memory))
}

#[derive(Clone)]
enum MethodScopeInput {
    Raw {
        logical: Option<u32>,
    },
    Archive {
        entry: ZipArchiveEntry,
        logical: Option<u32>,
    },
}

fn resolve_method_scope(
    artifact: &Artifact,
    scope: &MethodScope,
) -> Result<Vec<MethodScopeInput>, Error> {
    let mut inputs = Vec::new();
    match scope {
        MethodScope::Root => {
            if artifact.roots.is_empty() {
                return Err(Error::new(ErrorKind::NotFound)
                    .with_context("the archive contains no root DEX entry to analyse"));
            }
            for root in &artifact.roots {
                match &root.source {
                    RootSource::Raw => inputs.push(MethodScopeInput::Raw { logical: None }),
                    RootSource::Archive(entry) => inputs.push(MethodScopeInput::Archive {
                        entry: entry.clone(),
                        logical: None,
                    }),
                }
            }
        }
        MethodScope::AllDetected => {
            match &artifact.catalog {
                None => inputs.push(MethodScopeInput::Raw { logical: None }),
                Some(catalog) => {
                    // Detection is based on content, not the entry name:
                    // assets/renamed.bin is still a DEX provider. A bad
                    // extension-named entry remains selected by the explicit
                    // root/entry scopes, while AllDetected only admits a
                    // content probe that can actually be a DEX image.
                    for entry in &catalog.entries {
                        if zip::entry_starts_with_dex_magic(&artifact.bytes, entry) {
                            inputs.push(MethodScopeInput::Archive {
                                entry: entry.clone(),
                                logical: None,
                            });
                        }
                    }
                }
            }
        }
        MethodScope::Entries(ids) => {
            let catalog = artifact.catalog.as_ref().ok_or_else(|| {
                Error::new(ErrorKind::UnsupportedFormat)
                    .with_context("raw DEX input has no archive entries")
            })?;
            let mut seen = std::collections::BTreeSet::new();
            for id in ids {
                if id.artifact() != artifact.id {
                    return Err(Error::invalid_query(
                        "method scope entry belongs to a different artifact",
                    ));
                }
                if !seen.insert(id.ordinal()) {
                    continue;
                }
                let entry = catalog
                    .entries
                    .iter()
                    .find(|entry| entry.ordinal == id.ordinal())
                    .ok_or_else(|| {
                        Error::invalid_query(format!(
                            "method scope entry ordinal {} does not exist in this artifact",
                            id.ordinal()
                        ))
                    })?;
                inputs.push(MethodScopeInput::Archive {
                    entry: entry.clone(),
                    logical: None,
                });
            }
        }
        MethodScope::Dexes(ids) => {
            let catalog = artifact.catalog.as_ref();
            let mut seen = std::collections::BTreeSet::new();
            for id in ids {
                if id.artifact() != artifact.id {
                    return Err(Error::invalid_query(
                        "method scope DEX belongs to a different artifact",
                    ));
                }
                if id.entry_ordinal() == 0 && catalog.is_none() {
                    if !seen.insert((0, id.logical_ordinal())) {
                        continue;
                    }
                    inputs.push(MethodScopeInput::Raw {
                        logical: Some(id.logical_ordinal()),
                    });
                    continue;
                }
                let catalog = catalog.ok_or_else(|| {
                    Error::new(ErrorKind::UnsupportedFormat)
                        .with_context("raw DEX input has no archive entries")
                })?;
                let entry = catalog
                    .entries
                    .iter()
                    .find(|entry| entry.ordinal == id.entry_ordinal())
                    .ok_or_else(|| {
                        Error::invalid_query(format!(
                            "method scope DEX entry ordinal {} does not exist in this artifact",
                            id.entry_ordinal()
                        ))
                    })?;
                if !seen.insert((id.entry_ordinal(), id.logical_ordinal())) {
                    continue;
                }
                inputs.push(MethodScopeInput::Archive {
                    entry: entry.clone(),
                    logical: Some(id.logical_ordinal()),
                });
            }
        }
    }
    inputs.sort_by_key(|input| match input {
        MethodScopeInput::Raw { logical } => (0, 0, logical.unwrap_or(u32::MAX)),
        MethodScopeInput::Archive { entry, logical } => (
            1,
            entry.ordinal,
            logical.unwrap_or(u32::MAX),
        ),
    });
    Ok(inputs)
}

fn declared_scope_bytes(artifact: &Artifact, inputs: &[MethodScopeInput]) -> u64 {
    let mut total = 0u64;
    let mut seen_entries = std::collections::BTreeSet::new();
    for input in inputs {
        match input {
            MethodScopeInput::Raw { .. } if seen_entries.insert(0) => {
                total = total.saturating_add(artifact.bytes.len() as u64)
            }
            MethodScopeInput::Archive { entry, .. } if seen_entries.insert(entry.ordinal) => {
                total = total.saturating_add(entry.declared_uncompressed_bytes())
            }
            MethodScopeInput::Archive { .. } | MethodScopeInput::Raw { .. } => {}
        }
    }
    total
}

/// Runs a DEX operation over an explicit method scope. The archive entry
/// decode account is shared across all logical members and all selected
/// physical entries, just as it is for the root fold.
fn fold_scope<T: Send>(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
    measure: impl Fn(&T) -> (usize, usize, u64),
    mut op: impl FnMut(
        &container::DexEntryViews<'_>,
        usize,
        &ControlProbe<'_>,
    ) -> Result<Vec<T>, Error>,
) -> Result<(Vec<T>, Vec<Diagnostic>, Vec<MemoryPermit>), Error> {
    let inputs = resolve_method_scope(artifact, scope)?;
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let input_limits = artifact.limits.input();
    let declared_total = declared_scope_bytes(artifact, &inputs);
    if declared_total > input_limits.max_total_decoded_bytes {
        return Err(Error::resource_limit(format!(
            "the selected scope declares {declared_total} decoded bytes, above the {} per-operation limit",
            input_limits.max_total_decoded_bytes
        )));
    }
    let decoded = AtomicU64::new(0);
    let mut rows = Vec::new();
    let mut integrity = Vec::new();
    // Keep each DEX scan estimate until its rows have been transferred into
    // the final result and the caller has reserved the report allocation.
    let mut work_memory = Vec::new();
    let mut used = (0usize, 0usize, 0u64);
    for input in inputs {
        probe.check()?;
        let _decode_permit = match &input {
            MethodScopeInput::Archive { entry, .. } => Some(artifact.runtime.memory.reserve_with_limit(
                entry.declared_uncompressed_bytes(),
                artifact.limits.max_engine_owned_bytes,
                "decoded scoped DEX entry",
            )?),
            MethodScopeInput::Raw { .. } => None,
        };
        let (buffer, ordinal, raw_name, wanted_logical) = match input {
            MethodScopeInput::Raw { logical } => (None, 0, b"<memory.dex>".to_vec(), logical),
            MethodScopeInput::Archive { entry, logical } => {
                let ordinal = entry.ordinal;
                let raw_name = entry.raw_name.clone();
                let data = zip::read_entry(
                    &artifact.bytes,
                    &entry,
                    &input_limits,
                    &decoded,
                    &probe,
                )?;
                (Some(data), ordinal, raw_name, logical)
            }
        };
        let data = buffer.as_deref().unwrap_or(&artifact.bytes);
        let (views, entry_integrity) = container::validate_dex_entry(
            artifact.id,
            ordinal,
            &raw_name,
            data,
            &probe,
        )?;
        integrity.extend(entry_integrity);
        if wanted_logical.is_some_and(|wanted| wanted as usize >= views.views.len()) {
            return Err(Error::invalid_query("selected logical DEX does not exist"));
        }
        for (logical, _view) in views.views.iter().enumerate() {
            if wanted_logical.is_some_and(|wanted| wanted != logical as u32) {
                continue;
            }
            let entry = views.dex_entry(logical);
            let dex_view = dex::DexView::new(entry, views.views[logical].bytes());
            let work_bytes = dex::estimated_scan_work(&dex_view, &artifact.limits.scan)?;
            let scan_memory = artifact.runtime.memory.reserve_with_limit(
                work_bytes,
                artifact.limits.max_engine_owned_bytes,
                "scoped DEX scan working set",
            )?;
            let logical_rows = op(&views, logical, &probe)?;
            work_memory.push(scan_memory);
            for row in logical_rows {
                probe.check()?;
                charge_results(&mut used, measure(&row), &artifact.limits.scan)?;
                rows.push(row);
            }
        }
    }
    let diagnostics = artifact
        .open_diagnostics
        .iter()
        .cloned()
        .chain(integrity)
        .collect();
    Ok((rows, diagnostics, work_memory))
}

#[cfg(feature = "decompile")]
fn method_declaration_size(row: &MethodDeclaration) -> (usize, usize, u64) {
    let identity = row.identity();
    let text = |value: &DexText| value.unit_len().saturating_mul(2);
    let prototype = identity.prototype().parameters().iter().fold(
        text(identity.prototype().return_type()),
        |size, parameter| size.saturating_add(std::mem::size_of::<DexText>()).saturating_add(text(parameter)),
    );
    let class = row.class();
    let bytes = std::mem::size_of::<MethodDeclaration>()
        .saturating_add(text(identity.owner()))
        .saturating_add(text(identity.name()))
        .saturating_add(prototype)
        .saturating_add(identity.dex().raw_entry_name().len())
        .saturating_add(class.dex().raw_entry_name().len())
        .saturating_add(class.descriptor().as_str().len())
        .saturating_add(text(class.java_name()))
        .saturating_add(text(class.package()))
        .saturating_add(text(class.simple_name()));
    // Vectors may double capacity on growth. Reserve that storage in the
    // result projection, including empty-slot MethodDeclaration headers.
    (1, bytes.saturating_mul(2), 0)
}

#[cfg(feature = "decompile")]
fn field_declaration_size(row: &FieldDeclaration) -> (usize, usize, u64) {
    let text = |value: &DexText| value.unit_len().saturating_mul(2);
    let value_size = row
        .initial_value()
        .map(encoded_value_size)
        .unwrap_or(0);
    (
        1,
        256usize
            .saturating_add(text(row.owner()))
            .saturating_add(text(row.name()))
            .saturating_add(text(row.field_type()))
            .saturating_add(value_size),
        0,
    )
}

#[cfg(feature = "decompile")]
fn encoded_value_size(value: &EncodedValue) -> usize {
    match value {
        EncodedValue::Null
        | EncodedValue::Boolean(_)
        | EncodedValue::Byte(_)
        | EncodedValue::Short(_)
        | EncodedValue::Int(_)
        | EncodedValue::Long(_)
        | EncodedValue::Char(_)
        | EncodedValue::Float(_)
        | EncodedValue::Double(_) => 16,
        EncodedValue::String(text) | EncodedValue::Type(text) => 16 + text.unit_len() * 2,
        EncodedValue::Field {
            owner,
            name,
            field_type,
        } => 24 + (owner.unit_len() + name.unit_len() + field_type.unit_len()) * 2,
        EncodedValue::Method {
            owner,
            name,
            prototype,
        } => {
            24 + (owner.unit_len() + name.unit_len()) * 2
                + prototype
                    .parameters()
                    .iter()
                    .fold(prototype.return_type().unit_len() * 2, |n, p| {
                        n.saturating_add(p.unit_len() * 2)
                    })
        }
        EncodedValue::Enum { owner, name } => 24 + (owner.unit_len() + name.unit_len()) * 2,
        EncodedValue::Array(values) => 24usize.saturating_add(
            values
                .iter()
                .map(encoded_value_size)
                .fold(0usize, usize::saturating_add),
        ),
        EncodedValue::Annotation(annotation) => 32usize.saturating_add(
            annotation.items().iter().fold(0usize, |n, (name, value)| {
                n.saturating_add(name.unit_len() * 2)
                    .saturating_add(encoded_value_size(value))
            }),
        ),
    }
}

#[cfg(feature = "decompile")]
fn map_backend_prototype(
    dex: &droidsaw_dex::DexFile,
    proto_idx: u32,
) -> Result<Prototype, Error> {
    let proto = dex
        .protos
        .get(proto_idx as usize)
        .ok_or_else(|| Error::malformed_input(format!("prototype index {proto_idx} is outside the DEX")))?;
    let return_type = dex
        .get_type_descriptor(proto.return_type_idx)
        .map_err(|error| Error::malformed_input(format!("prototype return type: {error}")))?;
    let parameters = dex
        .type_lists
        .get(&proto.parameters_off)
        .map(|items| {
            items
                .iter()
                .filter_map(|type_idx| dex.get_type_descriptor(*type_idx).ok())
                .map(DexText::from_str_lossless)
                .collect()
        })
        .unwrap_or_default();
    Ok(Prototype::new(
        parameters,
        DexText::from_str_lossless(return_type),
    ))
}

#[cfg(feature = "decompile")]
fn map_backend_encoded_value(
    dex: &droidsaw_dex::DexFile,
    value: &droidsaw_dex::annotation::EncodedValue,
    depth: usize,
) -> Result<EncodedValue, Error> {
    if depth > 128 {
        return Err(Error::resource_limit(
            "encoded static value nesting exceeds the 128 level limit",
        ));
    }
    use droidsaw_dex::annotation::EncodedValue as B;
    let text = |index: u32, kind: &str| {
        dex.get_string(droidsaw_dex::ids::StringIdx(index))
            .map(DexText::from_str_lossless)
            .map_err(|error| Error::malformed_input(format!("{kind} string index {index}: {error}")))
    };
    let type_text = |index: u32, kind: &str| {
        dex.get_type_descriptor(droidsaw_dex::ids::TypeIdx(index))
            .map(DexText::from_str_lossless)
            .map_err(|error| Error::malformed_input(format!("{kind} type index {index}: {error}")))
    };
    match value {
        B::Byte(value) => Ok(EncodedValue::Byte(*value)),
        B::Short(value) => Ok(EncodedValue::Short(*value)),
        B::Char(value) => Ok(EncodedValue::Char(*value)),
        B::Int(value) => Ok(EncodedValue::Int(*value)),
        B::Long(value) => Ok(EncodedValue::Long(*value)),
        B::Float(value) => Ok(EncodedValue::Float(value.to_bits())),
        B::Double(value) => Ok(EncodedValue::Double(value.to_bits())),
        B::String(index) => Ok(EncodedValue::String(text(index.0, "value")?)),
        B::Type(index) => Ok(EncodedValue::Type(type_text(index.0, "value")?)),
        B::Null => Ok(EncodedValue::Null),
        B::Boolean(value) => Ok(EncodedValue::Boolean(*value)),
        B::Field(index) => {
            let field = dex.fields.get(index.0 as usize).ok_or_else(|| {
                Error::malformed_input(format!("field value index {} is outside the DEX", index.0))
            })?;
            Ok(EncodedValue::Field {
                owner: type_text(field.class_idx.0, "field owner")?,
                name: text(field.name_idx.0, "field name")?,
                field_type: type_text(field.type_idx.0, "field type")?,
            })
        }
        B::Method(index) => {
            let method = dex.methods.get(index.0 as usize).ok_or_else(|| {
                Error::malformed_input(format!("method value index {} is outside the DEX", index.0))
            })?;
            Ok(EncodedValue::Method {
                owner: type_text(method.class_idx.0, "method owner")?,
                name: text(method.name_idx.0, "method name")?,
                prototype: map_backend_prototype(dex, method.proto_idx.0)?,
            })
        }
        B::Enum(index) => {
            let field = dex.fields.get(index.0 as usize).ok_or_else(|| {
                Error::malformed_input(format!("enum value index {} is outside the DEX", index.0))
            })?;
            Ok(EncodedValue::Enum {
                owner: type_text(field.class_idx.0, "enum owner")?,
                name: text(field.name_idx.0, "enum name")?,
            })
        }
        B::Array(values) => Ok(EncodedValue::Array(
            values
                .iter()
                .map(|value| map_backend_encoded_value(dex, value, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        B::Annotation(annotation) => {
            let items = annotation
                .elements
                .iter()
                .map(|(name, value)| {
                    Ok((
                        text(name.0, "annotation name")?,
                        map_backend_encoded_value(dex, value, depth + 1)?,
                    ))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(EncodedValue::Annotation(crate::model::AnnotationRecord::new(
                AnnotationVisibility::Runtime,
                type_text(annotation.type_idx.0, "annotation type")?,
                items,
                String::new(),
            )))
        }
        B::MethodType(index) => Ok(EncodedValue::Type(DexText::from_str_lossless(&format!(
            "proto#{}",
            index.0
        )))),
        B::MethodHandle(index) => Ok(EncodedValue::Long(i64::from(index.0))),
    }
}

#[cfg(feature = "decompile")]
fn backend_static_value(
    dex: &droidsaw_dex::DexFile,
    class_def_idx: usize,
    field_idx: u32,
) -> Result<Option<EncodedValue>, Error> {
    let class_def = dex
        .class_defs
        .get(class_def_idx)
        .ok_or_else(|| Error::malformed_input("class definition index outside backend DEX"))?;
    let Some(class_data) = dex.class_datas.get(&class_def.class_data_off) else {
        return Ok(None);
    };
    let Some(static_position) = class_data
        .static_fields
        .iter()
        .position(|field| field.field_idx.0 == field_idx)
    else {
        return Ok(None);
    };
    let Some(values) = dex.encoded_arrays.get(&class_def.static_values_off) else {
        return Ok(None);
    };
    values
        .get(static_position)
        .map(|value| map_backend_encoded_value(dex, value, 0))
        .transpose()
}

#[cfg(feature = "decompile")]
fn method_declarations_for_parsed(
    parsed: &droidsaw_dex::analysis::ParsedDex<'_>,
    entry: &DexEntry,
    view: &ValidatedDexView<'_>,
    backend_bytes: &[u8],
    control: &ControlProbe<'_>,
) -> Result<Vec<MethodDeclaration>, Error> {
    let mut declarations = Vec::new();
    for class_summary in parsed.dex().list_classes() {
        control.check()?;
        let descriptor = ClassDescriptor::from_normalized(class_summary.descriptor.clone())
            .map_err(|error| {
                Error::malformed_input(format!(
                    "class_def {} has invalid descriptor: {error}",
                    class_summary.class_idx
                ))
            })?;
        let class_id = ClassId::new(view.id(), class_summary.class_idx as u32);
        let class = Class::new(class_id, entry.clone(), descriptor);
        let rows = parsed
            .dex()
            .list_methods(class_summary.class_idx, backend_bytes)
            .map_err(|error| {
                map_backend_error(droidsaw_dex::analysis::BackendError::Dex(error))
                    .with_context("backend method declaration parse")
            })?;
        for summary in rows {
            control.check()?;
            let method_id = MethodId::new(view.id(), summary.method_idx);
            let identity = MethodIdentity::new(
                method_id,
                entry.clone(),
                DexText::from_str_lossless(class.descriptor().as_str()),
                DexText::from_str_lossless(&summary.name),
                Prototype::new(
                    summary
                        .parameters
                        .iter()
                        .map(|parameter| DexText::from_str_lossless(parameter))
                        .collect(),
                    DexText::from_str_lossless(&summary.return_type),
                ),
            );
            declarations.push(MethodDeclaration::new(
                MethodTarget::new(class_id, method_id),
                identity,
                class.clone(),
                summary.access_flags,
                summary.is_direct,
                summary.has_code,
                summary.code_off,
            ));
        }
    }
    declarations.sort_by_key(MethodDeclaration::target);
    Ok(declarations)
}

#[cfg(feature = "decompile")]
fn render_method_from_parsed(
    parsed: &droidsaw_dex::analysis::ParsedDex<'_>,
    entry: &DexEntry,
    view: &ValidatedDexView<'_>,
    target: &MethodTarget,
    backend_bytes: &[u8],
    guard: &ControlGuard,
    artifact: &Artifact,
) -> Result<Report<Source>, Error> {
    if target.class().dex() != view.id() || target.method().dex() != view.id() {
        return Err(Error::invalid_query("method target is outside the selected DEX view"));
    }
    let class_def_idx = usize::try_from(target.class().class_def_idx()).map_err(|_| {
        Error::invalid_query("method target class_def index cannot fit the host index")
    })?;
    let class_def = parsed
        .dex()
        .class_defs
        .get(class_def_idx)
        .ok_or_else(|| Error::invalid_query("method target class_def index does not exist"))?;
    let descriptor = parsed
        .dex()
        .get_type_descriptor(class_def.class_idx)
        .map_err(|error| Error::malformed_input(format!("selected class descriptor: {error}")))?;
    let class = build_class(entry, view, target.class().class_def_idx(), descriptor);
    let budget = guard.backend_budget(backend_bytes.len() as u64, artifact);
    let report = droidsaw_dex::analysis::decompile_method_checked(
        parsed,
        class_def_idx,
        target.method().method_idx(),
        &droidsaw_dex::analysis::EmitOptions::default(),
        &budget,
        &guard.backend,
    )
    .map_err(|error| {
        map_backend_error(error).with_context("backend batch selected-method decompile")
    })?;
    let source = Source::new(
        class,
        normalize_source_text(&report.source),
        map_metadata(&report.metadata, &parsed, backend_bytes),
    );
    let memory = reserve_report_memory(artifact, source.owned_bytes(), &[], "batch source report")?;
    match report.completeness {
        droidsaw_dex::analysis::Completeness::Complete => Ok(Report::new(source, Vec::new(), OperationStats::default()).with_memory(memory)),
        droidsaw_dex::analysis::Completeness::Incomplete { reasons } => {
            Err(Error::new(ErrorKind::IncompleteDecompilation)
                .with_context(format!("incomplete selected-method decompilation: {reasons:?}"))
                .with_partial_source(source)
                .with_memory(memory))
        }
    }
}

#[cfg(feature = "decompile")]
fn visit_method_sources<F>(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
    selected_methods: Option<&[MethodTarget]>,
    mut visitor: F,
) -> Result<(), Error>
where
    F: FnMut(&MethodDeclaration, Result<&Source, &Error>) -> Result<(), Error>,
{
    let _selection_memory = selected_methods.map(|methods| {
        if methods.len() > artifact.limits.scan.max_result_items {
            return Err(Error::resource_limit("selected method count exceeds result-item limit"));
        }
        let per_target = std::mem::size_of::<MethodTarget>() * 4
            + std::mem::size_of::<(crate::model::DexId, Vec<MethodTarget>)>();
        let bytes = (methods.len() as u64).checked_mul(per_target as u64)
            .ok_or_else(|| Error::resource_limit("selected method index size overflow"))?;
        artifact.runtime.memory.reserve_with_limit(bytes, artifact.limits.max_engine_owned_bytes,
            "selected method target index")
    }).transpose()?;
    let selected_targets = selected_methods.map(|methods| {
        let mut targets = methods.to_vec();
        targets.sort_unstable();
        targets
    });
    if let Some(targets) = selected_targets.as_ref() {
        for target in targets {
            if target.class().dex().artifact() != artifact.id
                || target.method().dex().artifact() != artifact.id
            {
                return Err(Error::invalid_query(
                    "selected method target belongs to a different artifact",
                ));
            }
            if target.class().dex() != target.method().dex() {
                return Err(Error::invalid_query(
                    "selected method target class and method belong to different DEXes",
                ));
            }
        }
        if targets.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::invalid_query(
                "selected method targets contain a duplicate",
            ));
        }
        if targets.is_empty() {
            return Ok(());
        }
    }
    let selected_by_dex = selected_targets.as_ref().map(|targets| {
        let mut by_dex = std::collections::BTreeMap::new();
        for target in targets {
            by_dex
                .entry(target.method().dex())
                .or_insert_with(Vec::new)
                .push(*target);
        }
        by_dex
    });
    let mut selected_seen = std::collections::BTreeSet::new();
    let inputs = resolve_method_scope(artifact, scope)?;
    if let Some(targets) = &selected_targets {
        for target in targets {
            let dex = target.method().dex();
            if !inputs.iter().any(|input| match input {
                MethodScopeInput::Raw { logical } => dex.entry_ordinal() == 0
                    && logical.is_none_or(|ordinal| ordinal == dex.logical_ordinal()),
                MethodScopeInput::Archive { entry, logical } =>
                    entry.ordinal == dex.entry_ordinal()
                    && logical.is_none_or(|ordinal| ordinal == dex.logical_ordinal()),
            }) {
                return Err(Error::invalid_query("selected method target is outside the selected scope"));
            }
        }
    }
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let input_limits = artifact.limits.input();
    let declared_total = declared_scope_bytes(artifact, &inputs);
    if declared_total > input_limits.max_total_decoded_bytes {
        return Err(Error::resource_limit(format!(
            "the selected method scope declares {declared_total} decoded bytes, above the {} per-operation limit",
            input_limits.max_total_decoded_bytes
        )));
    }
    let decoded = AtomicU64::new(0);
    for input in inputs {
        probe.check()?;
        let _decode_permit = match &input {
            MethodScopeInput::Archive { entry, .. } => Some(artifact.runtime.memory.reserve_with_limit(
                entry.declared_uncompressed_bytes(),
                artifact.limits.max_engine_owned_bytes,
                "decoded batch method DEX entry",
            )?),
            MethodScopeInput::Raw { .. } => None,
        };
        let (buffer, ordinal, raw_name, wanted_logical) = match input {
            MethodScopeInput::Raw { logical } => (None, 0, b"<memory.dex>".to_vec(), logical),
            MethodScopeInput::Archive { entry, logical } => {
                let ordinal = entry.ordinal;
                let raw_name = entry.raw_name.clone();
                let data = zip::read_entry(
                    &artifact.bytes,
                    &entry,
                    &input_limits,
                    &decoded,
                    &probe,
                )?;
                (Some(data), ordinal, raw_name, logical)
            }
        };
        let data = buffer.as_deref().unwrap_or(&artifact.bytes);
        let (views, integrity) = container::validate_dex_entry(
            artifact.id,
            ordinal,
            &raw_name,
            data,
            &probe,
        )?;
        if wanted_logical.is_some_and(|wanted| wanted as usize >= views.views.len()) {
            return Err(Error::invalid_query("selected logical DEX does not exist"));
        }
        for (logical, view) in views.views.iter().enumerate() {
            let logical_u32 = u32::try_from(logical).map_err(|_| {
                Error::malformed_input("logical DEX ordinal exceeds the public identity range")
            })?;
            if wanted_logical.is_some_and(|wanted| wanted != logical_u32) {
                continue;
            }
            probe.check()?;
            let view_integrity: Vec<Diagnostic> = integrity
                .iter()
                .filter(|diagnostic| diagnostic.dex() == Some(view.id()))
                .cloned()
                .collect();
            let work_entry = views.dex_entry(logical);
            let work_view = dex::DexView::new(work_entry, view.bytes());
            let work_bytes = dex::estimated_scan_work(&work_view, &artifact.limits.scan)?;
            let _scan_memory = artifact.runtime.memory.reserve_with_limit(
                work_bytes,
                artifact.limits.max_engine_owned_bytes,
                "batch method DEX working set",
            )?;
            let _scratch_memory = artifact.runtime.memory.reserve_with_limit(
                container::backend_scratch_bytes(view, &view_integrity) as u64,
                artifact.limits.max_engine_owned_bytes, "backend normalization scratch",
            )?;
            let scratch = container::backend_scratch(view, &view_integrity);
            let backend_bytes = scratch
                .as_ref()
                .map(|scratch| scratch.bytes.as_slice())
                .unwrap_or_else(|| view.bytes());
            let budget = guard.backend_budget(backend_bytes.len() as u64, artifact);
            let parsed = droidsaw_dex::analysis::parse_for_analysis(
                backend_bytes,
                &droidsaw_dex::analysis::ParseOptions::default(),
                &budget,
                &guard.backend,
            )
            .map_err(|error| {
                map_backend_error(error).with_context("backend batch method parse")
            })?;
            let entry = views.dex_entry(logical);
            let declarations = method_declarations_for_parsed(
                &parsed,
                &entry,
                view,
                backend_bytes,
                &probe,
            )?;
            if let Some(wanted) = selected_by_dex
                .as_ref()
                .and_then(|by_dex| by_dex.get(&view.id()))
            {
                for wanted_target in wanted {
                    if !declarations.iter().any(|row| row.target() == *wanted_target) {
                        return Err(Error::invalid_query("selected method target is not declared in its selected DEX"));
                    }
                }
                for declaration in declarations {
                    let target = declaration.target();
                    if wanted.binary_search(&target).is_err() {
                        continue;
                    }
                    probe.check()?;
                    let result = render_method_from_parsed(
                        &parsed,
                        &entry,
                        view,
                        &target,
                        backend_bytes,
                        &guard,
                        artifact,
                    );
                    selected_seen.insert(target);
                    visitor(&declaration, result.as_ref().map(Report::value))?;
                }
            } else if selected_by_dex.is_none() {
                for declaration in declarations {
                    probe.check()?;
                    let result = render_method_from_parsed(
                        &parsed,
                        &entry,
                        view,
                        &declaration.target(),
                        backend_bytes,
                        &guard,
                        artifact,
                    );
                    visitor(&declaration, result.as_ref().map(Report::value))?;
                }
            }
        }
    }
    if let Some(targets) = selected_targets {
        for target in &targets {
            if !selected_seen.contains(target) {
                return Err(Error::invalid_query(
                    "selected method target is not declared in the selected scope",
                ));
            }
        }

    }
    Ok(())
}

#[cfg(feature = "decompile")]
fn visit_method_declarations<F>(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
    mut visitor: F,
) -> Result<(), Error>
where
    F: FnMut(&MethodDeclaration) -> Result<(), Error>,
{
    let inputs = resolve_method_scope(artifact, scope)?;
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let input_limits = artifact.limits.input();
    let declared_total = declared_scope_bytes(artifact, &inputs);
    if declared_total > input_limits.max_total_decoded_bytes {
        return Err(Error::resource_limit(format!(
            "the selected method scope declares {declared_total} decoded bytes, above the {} per-operation limit",
            input_limits.max_total_decoded_bytes
        )));
    }
    let decoded = AtomicU64::new(0);
    for input in inputs {
        probe.check()?;
        let _decode_permit = match &input {
            MethodScopeInput::Archive { entry, .. } => Some(artifact.runtime.memory.reserve_with_limit(
                entry.declared_uncompressed_bytes(),
                artifact.limits.max_engine_owned_bytes,
                "decoded method declaration DEX entry",
            )?),
            MethodScopeInput::Raw { .. } => None,
        };
        let (buffer, ordinal, raw_name, wanted_logical) = match input {
            MethodScopeInput::Raw { logical } => (None, 0, b"<memory.dex>".to_vec(), logical),
            MethodScopeInput::Archive { entry, logical } => {
                let ordinal = entry.ordinal;
                let raw_name = entry.raw_name.clone();
                let data = zip::read_entry(
                    &artifact.bytes,
                    &entry,
                    &input_limits,
                    &decoded,
                    &probe,
                )?;
                (Some(data), ordinal, raw_name, logical)
            }
        };
        let data = buffer.as_deref().unwrap_or(&artifact.bytes);
        let (views, integrity) = container::validate_dex_entry(
            artifact.id,
            ordinal,
            &raw_name,
            data,
            &probe,
        )?;
        if wanted_logical.is_some_and(|wanted| wanted as usize >= views.views.len()) {
            return Err(Error::invalid_query("selected logical DEX does not exist"));
        }
        for (logical, view) in views.views.iter().enumerate() {
            let logical_u32 = u32::try_from(logical).map_err(|_| {
                Error::malformed_input("logical DEX ordinal exceeds the public identity range")
            })?;
            if wanted_logical.is_some_and(|wanted| wanted != logical_u32) {
                continue;
            }
            probe.check()?;
            let view_integrity: Vec<Diagnostic> = integrity
                .iter()
                .filter(|diagnostic| diagnostic.dex() == Some(view.id()))
                .cloned()
                .collect();
            let work_entry = views.dex_entry(logical);
            let work_view = dex::DexView::new(work_entry, view.bytes());
            let work_bytes = dex::estimated_scan_work(&work_view, &artifact.limits.scan)?;
            let _scan_memory = artifact.runtime.memory.reserve_with_limit(
                work_bytes,
                artifact.limits.max_engine_owned_bytes,
                "method declaration DEX working set",
            )?;
            let _scratch_memory = artifact.runtime.memory.reserve_with_limit(
                container::backend_scratch_bytes(view, &view_integrity) as u64,
                artifact.limits.max_engine_owned_bytes,
                "backend normalization scratch",
            )?;
            let scratch = container::backend_scratch(view, &view_integrity);
            let backend_bytes = scratch
                .as_ref()
                .map(|scratch| scratch.bytes.as_slice())
                .unwrap_or_else(|| view.bytes());
            let budget = guard.backend_budget(backend_bytes.len() as u64, artifact);
            let parsed = droidsaw_dex::analysis::parse_for_analysis(
                backend_bytes,
                &droidsaw_dex::analysis::ParseOptions::default(),
                &budget,
                &guard.backend,
            )
            .map_err(|error| {
                map_backend_error(error)
                    .with_context("backend method declaration parse")
                    .with_diagnostics(integrity.clone())
            })?;
            let entry = views.dex_entry(logical);
            for declaration in method_declarations_for_parsed(
                &parsed,
                &entry,
                view,
                backend_bytes,
                &probe,
            )? {
                probe.check()?;
                visitor(&declaration)?;
            }
        }
    }
    Ok(())
}

#[cfg(feature = "decompile")]
fn method_inventory(
    artifact: &Artifact,
    scope: &MethodScope,
    control: &OperationControl,
) -> Result<Report<MethodInventory>, Error> {
    let inputs = resolve_method_scope(artifact, scope)?;
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let input_limits = artifact.limits.input();
    let declared_total = declared_scope_bytes(artifact, &inputs);
    if declared_total > input_limits.max_total_decoded_bytes {
        return Err(Error::resource_limit(format!(
            "the selected method scope declares {declared_total} decoded bytes, above the {} per-operation limit",
            input_limits.max_total_decoded_bytes
        )));
    }
    let decoded = AtomicU64::new(0);
    // Returned declarations survive each logical DEX parse. Keep its scratch
    // reservation until the final report has acquired ownership of the rows.
    let mut work_memory = Vec::new();
    let mut methods = Vec::new();
    let mut fields = Vec::new();
    let mut resolved_dexes = Vec::new();
    let mut dex_entries = Vec::new();
    let mut diagnostics = artifact.open_diagnostics.clone();
    let mut descriptor_counts = std::collections::BTreeMap::<String, usize>::new();
    let scan_limits = artifact.limits.scan;
    let mut used = (0usize, 0usize, 0u64);

    for input in inputs {
        probe.check()?;
        let _decode_memory = match &input {
            MethodScopeInput::Archive { entry, .. } => Some(artifact.runtime.memory.reserve_with_limit(
                entry.declared_uncompressed_bytes(),
                artifact.limits.max_engine_owned_bytes,
                "decoded method-inventory DEX entry",
            )?),
            MethodScopeInput::Raw { .. } => None,
        };
        let (buffer, ordinal, raw_name, wanted_logical) = match input {
            MethodScopeInput::Raw { logical } => (None, 0, b"<memory.dex>".to_vec(), logical),
            MethodScopeInput::Archive { entry, logical } => {
                let ordinal = entry.ordinal;
                let raw_name = entry.raw_name.clone();
                let data = zip::read_entry(
                    &artifact.bytes,
                    &entry,
                    &input_limits,
                    &decoded,
                    &probe,
                )?;
                (Some(data), ordinal, raw_name, logical)
            }
        };
        let data = buffer.as_deref().unwrap_or(&artifact.bytes);
        let (views, integrity) = container::validate_dex_entry(
            artifact.id,
            ordinal,
            &raw_name,
            data,
            &probe,
        )?;
        diagnostics.extend(integrity.clone());
        if wanted_logical.is_some_and(|wanted| wanted as usize >= views.views.len()) {
            return Err(Error::invalid_query("selected logical DEX does not exist"));
        }
        for (logical, view) in views.views.iter().enumerate() {
            let logical_u32 = u32::try_from(logical).map_err(|_| {
                Error::malformed_input("logical DEX ordinal exceeds the public identity range")
            })?;
            if wanted_logical.is_some_and(|wanted| wanted != logical_u32) {
                continue;
            }
            probe.check()?;
            let view_integrity: Vec<Diagnostic> = integrity
                .iter()
                .filter(|diagnostic| diagnostic.dex() == Some(view.id()))
                .cloned()
                .collect();
            let work_entry = views.dex_entry(logical);
            let work_view = dex::DexView::new(work_entry, view.bytes());
            let work_bytes = dex::estimated_scan_work(&work_view, &scan_limits)?;
            let scan_memory = artifact.runtime.memory.reserve_with_limit(
                work_bytes,
                artifact.limits.max_engine_owned_bytes,
                "method inventory DEX working set",
            )?;
            work_memory.push(scan_memory);
            let _scratch_memory = artifact.runtime.memory.reserve_with_limit(
                container::backend_scratch_bytes(view, &view_integrity) as u64,
                artifact.limits.max_engine_owned_bytes,
                "backend normalization scratch",
            )?;
            let scratch = container::backend_scratch(view, &view_integrity);
            let backend_bytes = scratch
                .as_ref()
                .map(|scratch| scratch.bytes.as_slice())
                .unwrap_or_else(|| view.bytes());
            let budget = guard.backend_budget(backend_bytes.len() as u64, artifact);
            let parsed = droidsaw_dex::analysis::parse_for_analysis(
                backend_bytes,
                &droidsaw_dex::analysis::ParseOptions::default(),
                &budget,
                &guard.backend,
            )
            .map_err(|error| {
                map_backend_error(error)
                    .with_context("backend method inventory parse")
                    .with_diagnostics(diagnostics.clone())
            })?;
            let entry = views.dex_entry(logical);
            resolved_dexes.push(view.id());
            dex_entries.push(entry.clone());
            for class_summary in parsed.dex().list_classes() {
                probe.check()?;
                let descriptor = ClassDescriptor::from_normalized(class_summary.descriptor.clone())
                    .map_err(|error| {
                        Error::malformed_input(format!(
                            "class_def {} has invalid descriptor: {error}",
                            class_summary.class_idx
                        ))
                    })?;
                let class_id = ClassId::new(view.id(), class_summary.class_idx as u32);
                let class = Class::new(class_id, entry.clone(), descriptor);
                *descriptor_counts
                    .entry(class.descriptor().as_str().to_owned())
                    .or_insert(0) += 1;
                let field_rows = parsed
                    .dex()
                    .list_fields(class_summary.class_idx, backend_bytes)
                    .map_err(|error| {
                        map_backend_error(droidsaw_dex::analysis::BackendError::Dex(error))
                            .with_context("backend field declaration parse")
                            .with_diagnostics(diagnostics.clone())
                    })?;
                for summary in field_rows {
                    probe.check()?;
                    let field_id = FieldId::new(view.id(), summary.field_idx);
                    let field = FieldDeclaration::new(
                        field_id,
                        class_id,
                        DexText::from_str_lossless(&class.descriptor().as_str()),
                        DexText::from_str_lossless(&summary.name),
                        DexText::from_str_lossless(&summary.field_type),
                        summary.access_flags,
                        summary.is_static,
                        if summary.is_static {
                            backend_static_value(
                                parsed.dex(),
                                class_summary.class_idx,
                                summary.field_idx,
                            )?
                        } else {
                            None
                        },
                    );
                    charge_results(&mut used, field_declaration_size(&field), &scan_limits)?;
                    fields.push(field);
                }
                let rows = parsed
                    .dex()
                    .list_methods(class_summary.class_idx, backend_bytes)
                    .map_err(|error| {
                        map_backend_error(droidsaw_dex::analysis::BackendError::Dex(error))
                            .with_context("backend class_data parse")
                            .with_diagnostics(diagnostics.clone())
                    })?;
                for summary in rows {
                    probe.check()?;
                    let method_id = MethodId::new(view.id(), summary.method_idx);
                    let target = MethodTarget::new(class_id, method_id);
                    let identity = MethodIdentity::new(
                        method_id,
                        entry.clone(),
                        DexText::from_str_lossless(&class.descriptor().as_str()),
                        DexText::from_str_lossless(&summary.name),
                        Prototype::new(
                            summary
                                .parameters
                                .iter()
                                .map(|parameter| DexText::from_str_lossless(parameter))
                                .collect(),
                            DexText::from_str_lossless(&summary.return_type),
                        ),
                    );
                    let row = MethodDeclaration::new(
                        target,
                        identity,
                        class.clone(),
                        summary.access_flags,
                        summary.is_direct,
                        summary.has_code,
                        summary.code_off,
                    );
                    charge_results(&mut used, method_declaration_size(&row), &scan_limits)?;
                    methods.push(row);
                }
            }
        }
    }
    methods.sort_by_key(MethodDeclaration::target);
    fields.sort_by_key(FieldDeclaration::id);
    resolved_dexes.sort();
    resolved_dexes.dedup();
    dex_entries.sort_by_key(DexEntry::id);
    dex_entries.dedup_by_key(|entry| entry.id());
    for (descriptor, count) in descriptor_counts {
        if count > 1 {
            diagnostics.push(Diagnostic::new(
                DiagnosticCode::DuplicateClassDefinition,
                Severity::Warning,
                Stage::Dex,
                format!(
                    "descriptor {descriptor} is defined {count} times; method identity retains class_def index"
                ),
            ));
        }
    }
    let stats = OperationStats {
        selected_dexes: resolved_dexes.len() as u32,
        scanned_methods: methods.len() as u64,
        result_items: (methods.len() + fields.len()) as u64,
        ..Default::default()
    };
    let memory = reserve_report_memory(artifact, used.1, &diagnostics, "method inventory report")?;
    drop(work_memory);
    Ok(Report::new(
        MethodInventory::new(scope.clone(), resolved_dexes, dex_entries, fields, methods),
        diagnostics,
        stats,
    )
    .with_memory(memory))
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
    decompile_with_scope(artifact, &MethodScope::Root, selector, control)
}

#[cfg(feature = "decompile")]
fn decompile_with_scope(
    artifact: &Artifact,
    scope: &MethodScope,
    selector: &ClassSelector,
    control: &OperationControl,
) -> Result<Report<Source>, Error> {
    let inputs = resolve_method_scope(artifact, scope)?;
    let declared_total = declared_scope_bytes(artifact, &inputs);
    if declared_total > artifact.limits.max_total_decoded_bytes {
        return Err(Error::resource_limit(format!(
            "the selected class scope declares {declared_total} decoded bytes, above the {} per-operation limit",
            artifact.limits.max_total_decoded_bytes
        )));
    }
    struct Resolved {
        entry_index: usize,
        logical: usize,
        class_def_idx: u32,
    }
    if let ClassSelector::Id(id) = selector
        && id.dex().artifact() != artifact.id
    {
        return Err(Error::invalid_query(
            "class id belongs to a different artifact",
        ));
    }
    if let ClassSelector::Descriptor(_, Some(id)) = selector
        && id.artifact() != artifact.id
    {
        return Err(Error::invalid_query(
            "DEX id belongs to a different artifact",
        ));
    }
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let decoded = AtomicU64::new(0);
    let mut resolution: Option<Resolved> = None;
    let mut selected_bytes = None;
    let mut selected_memory = None;
    let mut definitions = 0usize;
    let mut diagnostics = artifact.open_diagnostics.clone();
    // Visit the entire selected scope, keeping only the chosen entry alive.
    // This both certifies later entries and charges each inflation once.
    for (entry_index, input) in inputs.iter().enumerate() {
        probe.check()?;
        let decode_memory = match input {
            MethodScopeInput::Archive { entry, .. } => Some(artifact.runtime.memory.reserve_with_limit(
                entry.declared_uncompressed_bytes(),
                artifact.limits.max_engine_owned_bytes,
                "decoded class-scope DEX entry",
            )?),
            MethodScopeInput::Raw { .. } => None,
        };
        let (buffer, ordinal, raw_name) = match input {
            MethodScopeInput::Archive { entry, .. } => (
                Some(zip::read_entry(
                    &artifact.bytes,
                    entry,
                    &artifact.limits.input(),
                    &decoded,
                    &probe,
                )?),
                entry.ordinal,
                entry.raw_name.as_slice(),
            ),
            MethodScopeInput::Raw { .. } => (None, 0, b"<memory.dex>".as_slice()),
        };
        let data = buffer.as_deref().unwrap_or(&artifact.bytes);
        let (views, integrity) =
            container::validate_dex_entry(artifact.id, ordinal, raw_name, data, &probe)?;
        diagnostics.extend(integrity);
        let wanted_logical = match input {
            MethodScopeInput::Raw { logical } | MethodScopeInput::Archive { logical, .. } => {
                *logical
            }
        };
        if wanted_logical.is_some_and(|wanted| wanted as usize >= views.views.len()) {
            return Err(Error::invalid_query("selected logical DEX does not exist"));
        }
        let mut chose_entry = false;
        for (logical, view) in views.views.iter().enumerate() {
            if wanted_logical.is_some_and(|wanted| wanted != logical as u32) {
                continue;
            }
            let dex_view = dex::DexView::new(views.dex_entry(logical), view.bytes());
            let _resolution_memory = artifact.runtime.memory.reserve_with_limit(
                dex::estimated_scan_work(&dex_view, &artifact.limits.scan)?,
                artifact.limits.max_engine_owned_bytes,
                "class resolution working set",
            )?;
            let hits = match selector {
                ClassSelector::Descriptor(descriptor, pinned) => {
                    if pinned.is_some_and(|id| id != view.id()) {
                        continue;
                    }
                    dex::locate_class(&dex_view, descriptor, &artifact.limits.scan, Some(&probe))?
                }
                ClassSelector::Id(class_id) => {
                    if view.id() != class_id.dex() {
                        continue;
                    }
                    let classes =
                        dex::list_classes(&dex_view, &artifact.limits.scan, Some(&probe))?;
                    if !classes.iter().any(|class| class.id() == *class_id) {
                        return Err(Error::invalid_query("class_def index does not exist"));
                    }
                    vec![class_id.class_def_idx()]
                }
            };
            definitions += hits.len();
            if resolution.is_none()
                && let Some(&class_def_idx) = hits.first()
            {
                resolution = Some(Resolved {
                    entry_index,
                    logical,
                    class_def_idx,
                });
                chose_entry = true;
            }
        }
        if chose_entry {
            selected_bytes = buffer;
            selected_memory = decode_memory;
        }
    }
    let resolved = resolution.ok_or_else(|| {
        Error::new(ErrorKind::NotFound)
            .with_context("no selected DEX entry defines this class")
            .with_diagnostics(diagnostics.clone())
    })?;
    if definitions > 1 {
        diagnostics.push(Diagnostic::new(
            DiagnosticCode::DuplicateClassDefinition, Severity::Warning, Stage::Dex,
            format!("the descriptor is defined {definitions} times; the first (entry, logical, class_def) identity was decompiled"),
        ));
    }
    let input = &inputs[resolved.entry_index];
    let (ordinal, raw_name) = match input {
        MethodScopeInput::Archive { entry, .. } => (entry.ordinal, entry.raw_name.as_slice()),
        MethodScopeInput::Raw { .. } => (0, b"<memory.dex>".as_slice()),
    };
    let data = selected_bytes.as_deref().unwrap_or(&artifact.bytes);
    // Keep the selected decoded buffer's permit alive through backend parse,
    // rendering, and report construction. Non-selected entry permits were
    // released at the end of their loop iteration.
    let _selected_memory = selected_memory;
    // Recreate borrowed views; integrity diagnostics were collected once above.
    let (views, _) =
        container::validate_dex_entry(artifact.id, ordinal, raw_name, data, &probe)?;
    let view = &views.views[resolved.logical];
    // Only integrity findings about *this* view decide whether it needs the
    // normalization scratch; a checksum warning on another entry must not
    // cost a full copy here.
    let view_integrity: Vec<Diagnostic> = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.dex() == Some(view.id()))
        .cloned()
        .collect();
    let work_entry = views.dex_entry(resolved.logical);
    let work_view = dex::DexView::new(work_entry, view.bytes());
    let work_bytes = dex::estimated_scan_work(&work_view, &artifact.limits.scan)?;
    let _scan_memory = artifact.runtime.memory.reserve_with_limit(
        work_bytes,
        artifact.limits.max_engine_owned_bytes,
        "decompile DEX working set",
    )?;
    let _scratch_memory = artifact.runtime.memory.reserve_with_limit(
                container::backend_scratch_bytes(view, &view_integrity) as u64,
                artifact.limits.max_engine_owned_bytes,
                "backend normalization scratch",
            )?;
            let scratch = container::backend_scratch(view, &view_integrity);
    let backend_bytes: &[u8] = match &scratch {
        Some(scratch_view) => &scratch_view.bytes,
        None => view.bytes(),
    };
    // The host's cancel flag and deadline are mirrored into the backend
    // token/budget so the backend's own checkpoints honor them, and the
    // budget caps the parse at exactly this view's length.
    let budget = guard.backend_budget(u64::try_from(backend_bytes.len()).unwrap_or(u64::MAX), artifact);
    let parsed = droidsaw_dex::analysis::parse_for_analysis(
        backend_bytes,
        &droidsaw_dex::analysis::ParseOptions::default(),
        &budget,
        &guard.backend,
    )
    .map_err(|error| {
        map_backend_error(error)
            .with_context("backend parse")
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
        map_backend_error(error)
            .with_context("backend decompile")
            .with_diagnostics(diagnostics.clone())
    })?;

    let class_def = &parsed.dex().class_defs[resolved.class_def_idx as usize];
    let descriptor_text = parsed
        .dex()
        .get_type_descriptor(class_def.class_idx)
        .unwrap_or("L?;")
        .to_owned();
    let entry_row = views.dex_entry(resolved.logical);
    let class = build_class(&entry_row, view, resolved.class_def_idx, &descriptor_text);
    let metadata = map_metadata(&report.metadata, &parsed, backend_bytes);
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
            let stats = OperationStats {
                result_items: 1,
                ..Default::default()
            };
            let memory = reserve_report_memory(
                artifact,
                source.owned_bytes(),
                &diagnostics,
                "decompile report",
            )?;
            Ok(Report::new(source, diagnostics, stats).with_memory(memory))
        }
        droidsaw_dex::analysis::Completeness::Incomplete { reasons } => {
            let memory = reserve_report_memory(
                artifact, source.owned_bytes(), &diagnostics, "partial source report",
            )?;
            Err(Error::new(ErrorKind::IncompleteDecompilation)
                .with_context(format!("incomplete decompilation: {reasons:?}"))
                .with_diagnostics(diagnostics)
                .with_partial_source(source)
                .with_memory(memory))
        }
    }
}

#[cfg(feature = "decompile")]
fn decompile_selected_method(
    artifact: &Artifact,
    target: &MethodTarget,
    control: &OperationControl,
) -> Result<Report<Source>, Error> {
    let class_id = target.class();
    let method_id = target.method();
    if class_id.dex().artifact() != artifact.id || method_id.dex().artifact() != artifact.id {
        return Err(Error::invalid_query(
            "method target belongs to a different artifact",
        ));
    }
    if class_id.dex() != method_id.dex() {
        return Err(Error::invalid_query(
            "method target class and method belong to different DEX identities",
        ));
    }
    let guard = ControlGuard::new(control);
    let probe = guard.probe();
    let decoded = AtomicU64::new(0);
    let (buffer, ordinal, raw_name, decode_memory) = if let Some(catalog) = &artifact.catalog {
        let entry = catalog
            .entries
            .iter()
            .find(|entry| entry.ordinal == method_id.dex().entry_ordinal())
            .ok_or_else(|| {
                Error::invalid_query(format!(
                    "method target entry ordinal {} does not exist in this artifact",
                    method_id.dex().entry_ordinal()
                ))
            })?;
        let ordinal = entry.ordinal;
        let raw_name = entry.raw_name.clone();
        let decode_memory = artifact.runtime.memory.reserve_with_limit(
            entry.declared_uncompressed_bytes(),
            artifact.limits.max_engine_owned_bytes,
            "decoded selected-method DEX entry",
        )?;
        let data = zip::read_entry(
            &artifact.bytes,
            entry,
            &artifact.limits.input(),
            &decoded,
            &probe,
        )?;
        (Some(data), ordinal, raw_name, Some(decode_memory))
    } else {
        if method_id.dex().entry_ordinal() != 0 || method_id.dex().logical_ordinal() != 0 {
            return Err(Error::invalid_query(
                "raw DEX method target must use entry/logical ordinal zero",
            ));
        }
        let decoded = u64::try_from(artifact.bytes.len()).unwrap_or(u64::MAX);
        if decoded > artifact.limits.max_total_decoded_bytes {
            return Err(Error::resource_limit(format!(
                "raw DEX method input declares {decoded} decoded bytes, above the {} per-operation limit",
                artifact.limits.max_total_decoded_bytes
            )));
        }
        (None, 0, b"<memory.dex>".to_vec(), None)
    };
    let _decode_memory = decode_memory;
    let data = buffer.as_deref().unwrap_or(&artifact.bytes);
    let (views, integrity) = container::validate_dex_entry(
        artifact.id,
        ordinal,
        &raw_name,
        data,
        &probe,
    )?;
    let logical = usize::try_from(method_id.dex().logical_ordinal()).map_err(|_| {
        Error::invalid_query("method target logical DEX ordinal cannot fit the host index")
    })?;
    let view = views.views.get(logical).ok_or_else(|| {
        Error::invalid_query(format!(
            "method target logical DEX ordinal {} does not exist",
            method_id.dex().logical_ordinal()
        ))
    })?;
    if view.id() != method_id.dex() {
        return Err(Error::invalid_query("method target identity does not match the DEX view"));
    }
    let view_integrity: Vec<Diagnostic> = integrity
        .iter()
        .filter(|diagnostic| diagnostic.dex() == Some(view.id()))
        .cloned()
        .collect();
    let work_entry = views.dex_entry(logical);
    let work_view = dex::DexView::new(work_entry, view.bytes());
    let work_bytes = dex::estimated_scan_work(&work_view, &artifact.limits.scan)?;
    let _scan_memory = artifact.runtime.memory.reserve_with_limit(
        work_bytes,
        artifact.limits.max_engine_owned_bytes,
        "selected-method DEX working set",
    )?;
    let _scratch_memory = artifact.runtime.memory.reserve_with_limit(
                container::backend_scratch_bytes(view, &view_integrity) as u64,
                artifact.limits.max_engine_owned_bytes,
                "backend normalization scratch",
            )?;
            let scratch = container::backend_scratch(view, &view_integrity);
    let backend_bytes = scratch
        .as_ref()
        .map(|scratch| scratch.bytes.as_slice())
        .unwrap_or_else(|| view.bytes());
    let budget = guard.backend_budget(backend_bytes.len() as u64, artifact);
    let parsed = droidsaw_dex::analysis::parse_for_analysis(
        backend_bytes,
        &droidsaw_dex::analysis::ParseOptions::default(),
        &budget,
        &guard.backend,
    )
    .map_err(|error| {
        map_backend_error(error)
            .with_context("backend selected-method parse")
            .with_diagnostics(
                artifact
                    .open_diagnostics
                    .iter()
                    .cloned()
                    .chain(integrity.iter().cloned())
                    .collect(),
            )
    })?;
    let report = droidsaw_dex::analysis::decompile_method_checked(
        &parsed,
        class_id.class_def_idx() as usize,
        method_id.method_idx(),
        &droidsaw_dex::analysis::EmitOptions::default(),
        &budget,
        &guard.backend,
    )
    .map_err(|error| {
        map_backend_error(error)
            .with_context("backend selected-method decompile")
            .with_diagnostics(
                artifact
                    .open_diagnostics
                    .iter()
                    .cloned()
                    .chain(integrity.iter().cloned())
                    .collect(),
            )
    })?;
    let class_def = parsed
        .dex()
        .class_defs
        .get(class_id.class_def_idx() as usize)
        .ok_or_else(|| Error::invalid_query("class_def index does not exist"))?;
    let descriptor_text = parsed
        .dex()
        .get_type_descriptor(class_def.class_idx)
        .map_err(|_| Error::malformed_input("selected class descriptor cannot be resolved"))?;
    let entry = views.dex_entry(logical);
    let class = build_class(&entry, view, class_id.class_def_idx(), descriptor_text);
    let source = Source::new(
        class,
        normalize_source_text(&report.source),
        map_metadata(&report.metadata, &parsed, backend_bytes),
    );
    let mut diagnostics: Vec<Diagnostic> = artifact
        .open_diagnostics
        .iter()
        .cloned()
        .chain(integrity)
        .collect();
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
    match report.completeness {
        droidsaw_dex::analysis::Completeness::Complete => {
            let memory = reserve_report_memory(
                artifact,
                source.owned_bytes(),
                &diagnostics,
                "selected-method report",
            )?;
            Ok(Report::new(
                source,
                diagnostics,
                OperationStats {
                    result_items: 1,
                    scanned_methods: 1,
                    ..Default::default()
                },
            )
            .with_memory(memory))
        }
        droidsaw_dex::analysis::Completeness::Incomplete { reasons } => {
            let memory = reserve_report_memory(
                artifact, source.owned_bytes(), &diagnostics, "partial source report",
            )?;
            Err(Error::new(ErrorKind::IncompleteDecompilation)
                .with_context(format!("incomplete selected-method decompilation: {reasons:?}"))
                .with_diagnostics(diagnostics)
                .with_partial_source(source)
                .with_memory(memory))
        }
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
    let _decode_memory = artifact.runtime.memory.reserve_with_limit(
        entry.declared_uncompressed_bytes(),
        artifact.limits.max_engine_owned_bytes,
        "decoded manifest entry",
    )?;
    let decoded = AtomicU64::new(0);
    let bytes = zip::read_entry(
        &artifact.bytes,
        entry,
        &artifact.limits.input(),
        &decoded,
        &probe,
    )?;
    let (manifest, report_diagnostics, _report_stats) =
        crate::manifest::decode_manifest_entry(&bytes, &artifact.limits.manifest, control)?
            .into_unaccounted_parts();
    let diagnostics: Vec<Diagnostic> = report_diagnostics
        .into_iter()
        .chain(artifact.open_diagnostics.iter().cloned())
        .collect();
    let memory = reserve_report_memory(
        artifact,
        bytes.len().saturating_add(1024),
        &diagnostics,
        "manifest report",
    )?;
    Ok(Report::new(
        manifest,
        diagnostics,
        OperationStats {
            result_items: 1,
            ..Default::default()
        },
    )
    .with_memory(memory))
}

#[cfg(feature = "decompile")]
fn map_backend_error(error: droidsaw_dex::analysis::BackendError) -> Error {
    use crate::error::CancelCause;
    use droidsaw_dex::analysis::BackendError as Backend;
    let kind = match &error {
        Backend::Cancelled => ErrorKind::Cancelled {
            cause: CancelCause::User,
        },
        Backend::DeadlineExceeded => ErrorKind::Cancelled {
            cause: CancelCause::Deadline,
        },
        Backend::InputBudget { .. } | Backend::MemoryBudget { .. }
        | Backend::MemoryBoundOverflow { .. } => ErrorKind::ResourceLimit,
        Backend::InvalidClassDefIndex { .. } | Backend::InvalidMethodIndex { .. } => {
            ErrorKind::InvalidQuery
        }
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
    Class::new(
        ClassId::new(view.id(), class_def_idx),
        entry.clone(),
        descriptor,
    )
}

#[cfg(feature = "decompile")]
fn map_metadata(
    metadata: &droidsaw_dex::analysis::BackendMetadata,
    parsed: &droidsaw_dex::analysis::ParsedDex<'_>,
    bytes: &[u8],
) -> SourceMetadata {
    let class = ClassMetadata {
        access_flags: metadata.access_flags,
        super_class: metadata
            .super_descriptor
            .as_deref()
            .map(DexText::from_str_lossless),
        interfaces: metadata
            .interfaces
            .iter()
            .map(|text| DexText::from_str_lossless(text))
            .collect(),
        source_file: metadata
            .source_file
            .as_deref()
            .map(DexText::from_str_lossless),
        generic_signature: metadata
            .generic_signature
            .as_deref()
            .map(DexText::from_str_lossless),
        enclosing: metadata
            .enclosing
            .as_ref()
            .map(|enclosing| EnclosingRecord {
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
    let annotations: Vec<AnnotationEntry> = metadata
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
                }),
        )
        .collect();
    let class_data = parsed.dex().class_defs.get(metadata.class_def_idx)
        .and_then(|class| parsed.dex().class_datas.get(&class.class_data_off));
    let methods = metadata.method_reports.iter().map(|report| {
        let debug = class_data.and_then(|data| data.direct_methods.iter().chain(&data.virtual_methods)
            .find(|method| method.method_idx.0 == report.method_idx))
            .and_then(|method| parsed.dex().code_items.get(&method.code_off).map(|code| (method, code)))
            .and_then(|(method, code)| parsed.dex().debug_infos.get(&code.debug_info_off).map(|debug| {
                let end = crate::bytes::read_u32(bytes, method.code_off as usize + 12).unwrap_or(0);
                crate::model::DebugInfo {
                    parameter_names: debug.parameter_names.iter()
                        .map(|name| name.as_deref().map(DexText::from_str_lossless)).collect(),
                    locals: debug.locals.iter().map(|local| crate::model::LocalVariable {
                        name: DexText::from_str_lossless(local.name.as_deref().unwrap_or("")),
                        start_code_unit: local.start_addr,
                        end_code_unit: local.end_addr.unwrap_or(end),
                        slot: local.register,
                    }).collect(),
                    lines: debug.line_table.iter().map(|&(pc, line)| crate::model::LineNumberEntry {
                        code_unit: pc, line,
                    }).collect(),
                }
            }));
        let method_annotations = annotations.iter().filter(|annotation| match annotation.target {
            AnnotationTarget::Method { index } => index == report.method_idx as usize,
            AnnotationTarget::Parameter { method_index, .. } => method_index == report.method_idx as usize,
            _ => false,
        }).cloned().collect();
        MethodMetadata {
            name: DexText::from_str_lossless(&report.name),
            prototype: prototype_from_descriptor(&report.prototype),
            access_flags: report.access_flags,
            generic_signature: None,
            throws: Vec::new(),
            annotations: method_annotations,
            parameter_signatures: Vec::new(),
            debug,
        }
    }).collect();
    SourceMetadata {
        class,
        annotations,
        fields,
        methods,
    }
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
        T::Annotation {
            type_descriptor,
            elements,
        } => M::Annotation(crate::model::AnnotationRecord {
            visibility: crate::model::AnnotationVisibility::Runtime,
            type_descriptor: DexText::from_str_lossless(type_descriptor),
            items: elements
                .iter()
                .map(|(name, value)| (DexText::from_str_lossless(name), typed_to_encoded(value)))
                .collect(),
            rendered: render_annotation_elements(
                &elements
                    .iter()
                    .map(|(n, v)| (n.clone(), format!("{v:?}")))
                    .collect::<Vec<_>>(),
            ),
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
        Backend::Field { field_idx } => AnnotationTarget::Field {
            index: field_idx as usize,
        },
        Backend::Method { method_idx } => AnnotationTarget::Method {
            index: method_idx as usize,
        },
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
    use std::io::{self, Write};

    fn no_control() -> OperationControl {
        OperationControl::new()
    }

    #[test]
    fn class_relationship_report_clones_hold_memory_and_failures_release_it() {
        let mut bytes = const_string_fixture(1);
        let defs = crate::bytes::read_u32(&bytes, 0x64).unwrap() as usize;
        bytes[defs + 8..defs + 12].copy_from_slice(&1u32.to_le_bytes());
        let query = query::class_relation_query(
            crate::model::ClassRelationKind::Extends,
            "Fixture0",
            &Default::default(),
        )
        .unwrap();
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine
            .open_bytes(Arc::from(bytes.clone()), InputKind::Dex, &no_control())
            .unwrap();
        let baseline = engine.runtime.active_bytes.load(Ordering::Relaxed);
        let report = engine
            .class_relations(&artifact, &query, &no_control())
            .unwrap();
        assert_eq!(report.value().len(), 1);
        let retained = engine.runtime.active_bytes.load(Ordering::Relaxed);
        assert!(retained > baseline);
        let clone = report.clone();
        assert_eq!(
            engine.runtime.active_bytes.load(Ordering::Relaxed),
            retained
        );
        drop(report);
        assert_eq!(
            engine.runtime.active_bytes.load(Ordering::Relaxed),
            retained
        );
        drop(clone);
        assert_eq!(
            engine.runtime.active_bytes.load(Ordering::Relaxed),
            baseline
        );
        let peak = engine.runtime.memory.peak.load(Ordering::Relaxed);
        drop(artifact);
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), 0);
        let engine = Engine::new(EngineOptions {
            limits: Limits {
                max_engine_owned_bytes: peak - 1,
                ..Limits::default()
            },
            ..EngineOptions::default()
        })
        .unwrap();
        let artifact = engine
            .open_bytes(Arc::from(bytes), InputKind::Dex, &no_control())
            .unwrap();
        let baseline = engine.runtime.active_bytes.load(Ordering::Relaxed);
        let error = engine
            .class_relations(&artifact, &query, &no_control())
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::ResourceLimit);
        assert_eq!(
            engine.runtime.active_bytes.load(Ordering::Relaxed),
            baseline
        );
        let absent = query::class_relation_query(
            crate::model::ClassRelationKind::Extends,
            "Missing",
            &Default::default(),
        )
        .unwrap();
        drop(
            engine
                .class_relations(&artifact, &absent, &no_control())
                .unwrap(),
        );
        assert_eq!(
            engine.runtime.active_bytes.load(Ordering::Relaxed),
            baseline
        );
    }

    #[test]
    fn snapshot_stops_at_the_first_byte_above_the_actual_limit() {
        let mut growing = std::io::Cursor::new(vec![0u8; 128 * 1024]);
        let error = read_snapshot(&mut growing, 17, &no_control()).unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::ResourceLimit);
        assert_eq!(
            growing.position(),
            18,
            "do not read or retain the unbounded tail"
        );
        let small = read_snapshot(&mut std::io::Cursor::new(b"ok"), 2, &no_control()).unwrap();
        assert_eq!(small, b"ok");
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn backend_control_shares_live_cancellation_and_preserves_causes() {
        use crate::error::CancelCause;
        use droidsaw_dex::analysis::BackendError;
        let flag = Arc::new(AtomicBool::new(false));
        let control = OperationControl::new().with_cancel_flag(Arc::clone(&flag));
        let guard = ControlGuard::new(&control);
        assert!(!guard.backend.is_cancelled());
        flag.store(true, Ordering::Release);
        assert!(guard.backend.is_cancelled());
        assert_eq!(
            map_backend_error(BackendError::Cancelled).kind(),
            &ErrorKind::Cancelled {
                cause: CancelCause::User
            }
        );
        assert_eq!(
            map_backend_error(BackendError::DeadlineExceeded).kind(),
            &ErrorKind::Cancelled {
                cause: CancelCause::Deadline
            }
        );
        assert_eq!(
            map_backend_error(BackendError::InputBudget { bytes: 2, cap: 1 }).kind(),
            &ErrorKind::ResourceLimit
        );
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
    fn archive_entries_preserve_ordinal_raw_name_and_directory_facts() {
        let mut zip = build_zip(&[
            ("dup", b"first".as_slice(), false),
            ("dup", b"second".as_slice(), false),
            ("folder/", b"".as_slice(), false),
        ]);
        let positions: Vec<usize> = zip
            .windows(3)
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == b"dup").then_some(index))
            .collect();
        assert_eq!(
            positions.len(),
            4,
            "both duplicate names occur in local/CD headers"
        );
        for position in positions {
            zip[position..position + 3].copy_from_slice(b"d\xffp");
        }
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine
            .open_bytes(
                Arc::from(zip.into_boxed_slice()),
                InputKind::Apk,
                &no_control(),
            )
            .unwrap();
        let report = engine
            .archive_entries(&artifact, &ArchiveEntryQuery::default(), &no_control())
            .unwrap();
        assert_eq!(report.stats().result_items, 3);
        let entries = report.value();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].id().ordinal(), 0);
        assert_eq!(entries[1].id().ordinal(), 1);
        assert_ne!(entries[0].id(), entries[1].id());
        assert_eq!(entries[0].raw_name(), b"d\xffp");
        assert!(entries[0].display_name().contains("\\xff"));
        assert!(!entries[0].is_directory());
        assert!(entries[2].is_directory());

        let other_artifact = engine
            .open_bytes(
                Arc::from(
                    build_zip(&[("other", b"different".as_slice(), false)]).into_boxed_slice(),
                ),
                InputKind::Apk,
                &no_control(),
            )
            .unwrap();
        let other_entries = engine
            .archive_entries(
                &other_artifact,
                &ArchiveEntryQuery::default(),
                &no_control(),
            )
            .unwrap();
        let mut foreign_output = Vec::new();
        let error = engine
            .copy_entry(
                &artifact,
                other_entries.value()[0].id(),
                &mut foreign_output,
                &no_control(),
            )
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::InvalidQuery);
        assert!(foreign_output.is_empty());

        let error = engine
            .archive_entries(
                &artifact,
                &ArchiveEntryQuery {
                    max_items: 2,
                    ..ArchiveEntryQuery::default()
                },
                &no_control(),
            )
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::ResourceLimit);
        let error = engine
            .archive_entries(
                &artifact,
                &ArchiveEntryQuery {
                    max_result_bytes: 1,
                    ..ArchiveEntryQuery::default()
                },
                &no_control(),
            )
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::ResourceLimit);
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("test writer failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn copy_entry_streams_stored_and_deflate_with_shared_quota() {
        let first = vec![b'A'; 70 * 1024];
        let second = vec![b'B'; 70 * 1024];
        let bytes = Arc::from(
            build_zip(&[("one.bin", &first, false), ("two.bin", &second, true)]).into_boxed_slice(),
        );
        let limits = Limits {
            // Leave room for the writer-failure attempt after both successful
            // copies; that attempt must exercise sink rollback.
            max_total_decoded_bytes: (2 * first.len() + second.len()) as u64,
            ..Limits::default()
        };
        let engine = Engine::new(EngineOptions {
            limits,
            ..EngineOptions::default()
        })
        .unwrap();
        let artifact = engine
            .open_bytes(Arc::clone(&bytes), InputKind::Apk, &no_control())
            .unwrap();
        let entries = engine
            .archive_entries(&artifact, &ArchiveEntryQuery::default(), &no_control())
            .unwrap();
        let session = engine
            .archive_copy_session(&artifact, &no_control())
            .unwrap();
        let mut first_out = Vec::new();
        assert_eq!(
            session
                .copy_entry(entries.value()[0].id(), &mut first_out, &no_control())
                .unwrap(),
            first.len() as u64
        );
        assert_eq!(first_out, first);
        let mut second_out = Vec::new();
        assert_eq!(
            session
                .copy_entry(entries.value()[1].id(), &mut second_out, &no_control())
                .unwrap(),
            second.len() as u64
        );
        assert_eq!(second_out, second);

        let expired = OperationControl::new()
            .with_deadline(std::time::Instant::now() - Duration::from_secs(1));
        let mut cancelled_out = Vec::new();
        let error = session
            .copy_entry(entries.value()[0].id(), &mut cancelled_out, &expired)
            .unwrap_err();
        assert_eq!(
            *error.kind(),
            ErrorKind::Cancelled {
                cause: crate::error::CancelCause::Deadline
            }
        );
        assert!(cancelled_out.is_empty());

        let tight_limits = Limits {
            max_total_decoded_bytes: first.len() as u64,
            ..Limits::default()
        };
        let tight_engine = Engine::new(EngineOptions {
            limits: tight_limits,
            ..EngineOptions::default()
        })
        .unwrap();
        let tight_artifact = tight_engine
            .open_bytes(Arc::clone(&bytes), InputKind::Apk, &no_control())
            .unwrap();
        let tight_entries = tight_engine
            .archive_entries(
                &tight_artifact,
                &ArchiveEntryQuery::default(),
                &no_control(),
            )
            .unwrap();
        let tight_session = tight_engine
            .archive_copy_session(&tight_artifact, &no_control())
            .unwrap();
        let mut tight_first = Vec::new();
        tight_session
            .copy_entry(
                tight_entries.value()[0].id(),
                &mut tight_first,
                &no_control(),
            )
            .unwrap();
        let mut over_quota = Vec::new();
        let error = tight_session
            .copy_entry(
                tight_entries.value()[1].id(),
                &mut over_quota,
                &no_control(),
            )
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::ResourceLimit);
        assert!(
            over_quota.is_empty(),
            "quota failure happens before sink output"
        );

        let mut failed = FailingWriter;
        let error = session
            .copy_entry(entries.value()[0].id(), &mut failed, &no_control())
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput);
        assert!(error.to_string().contains("writer failed"));
    }

    #[test]
    fn copy_entry_crc_failure_rolls_back_shared_quota_for_reuse() {
        let first = b"bad crc entry".to_vec();
        let second = b"still readable".to_vec();
        let mut zip = build_zip(&[("first", &first, false), ("second", &second, false)]);
        let central = zip
            .windows(4)
            .position(|bytes| bytes == b"PK\x01\x02")
            .expect("central directory");
        zip[central + 16..central + 20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine
            .open_bytes(
                Arc::from(zip.into_boxed_slice()),
                InputKind::Apk,
                &no_control(),
            )
            .unwrap();
        let entries = engine
            .archive_entries(&artifact, &ArchiveEntryQuery::default(), &no_control())
            .unwrap();
        let session = engine
            .archive_copy_session(&artifact, &no_control())
            .unwrap();
        let mut discarded = Vec::new();
        let error = session
            .copy_entry(entries.value()[0].id(), &mut discarded, &no_control())
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput);
        assert!(error.to_string().contains("CRC-32 mismatch"));
        let mut second_out = Vec::new();
        session
            .copy_entry(entries.value()[1].id(), &mut second_out, &no_control())
            .unwrap();
        assert_eq!(second_out, second);
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
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let query =
            query::string_query("Authorization", MatchMode::Literal, &Default::default()).unwrap();
        let report = references(&artifact, &query, &no_control()).unwrap();
        assert!(!report.value().is_empty(), "fixture strings must hit");
        // central-directory order: every row of classes.dex precedes classes2.dex
        let first_ordinal = report.value()[0].caller().id().dex().entry_ordinal();
        let all_ordinals: Vec<u32> = report
            .value()
            .iter()
            .map(|row| row.caller().id().dex().entry_ordinal())
            .collect();
        assert!(
            all_ordinals.windows(2).all(|pair| pair[0] <= pair[1]),
            "rows must be merged in entry-ordinal order"
        );
        assert_eq!(first_ordinal, 0);
        // deterministic across runs
        let again = references(&artifact, &query, &no_control()).unwrap();
        assert_eq!(
            format!("{:?}", report.value()),
            format!("{:?}", again.value())
        );
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn dexless_archives_split_success_and_notfound_by_operation() {
        let zip = build_zip(&[("AndroidManifest.xml", b"<manifest/>".as_slice(), false)]);
        let path = temp_apk("a07-dexless", &zip);
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let dex_rows = dexes(&artifact, &no_control()).unwrap();
        assert!(
            dex_rows.value().is_empty(),
            "dexes on a dex-less APK is an empty catalog"
        );
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
        let limits = Limits {
            max_total_decoded_bytes: dex.len() as u64,
            ..Limits::default()
        };
        let artifact = open_path(&path, &limits, &test_runtime(), &no_control()).unwrap();
        let selector = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("Lexample/Statics;".to_owned()).unwrap(),
            None,
        );
        let report = decompile(&artifact, &selector, &no_control()).unwrap();
        let text = report.value().text();
        assert!(
            text.contains("FIRST = 11"),
            "FIRST initializer missing:\n{text}"
        );
        assert!(
            text.contains("SECOND = 22"),
            "SECOND initializer missing:\n{text}"
        );
        assert!(
            text.contains("SECOND"),
            "getSecond must read SECOND:\n{text}"
        );
        assert_eq!(
            report.value().class().descriptor().as_str(),
            "Lexample/Statics;"
        );
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
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let selector = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("Lexample/Statics;".to_owned()).unwrap(),
            None,
        );
        let report = decompile(&artifact, &selector, &no_control()).unwrap();
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == DiagnosticCode::DexChecksumMismatch)
        );
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn classes_lists_all_definitions_and_flags_duplicates() {
        // One descriptor defined in two different DEX entries.
        let first = const_string_fixture(1);
        let zip = build_zip(&[
            ("classes.dex", &first, true),
            ("classes2.dex", &first, true),
        ]);
        let path = temp_apk("a07-dup-classes", &zip);
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let report = classes(&artifact, &ClassFilter::none(), &no_control()).unwrap();
        assert_eq!(report.value().len(), 2, "both definitions are listed");
        let ids: Vec<u32> = report
            .value()
            .iter()
            .map(|class| class.id().class_def_idx())
            .collect();
        assert_eq!(ids, [0, 0], "both are class_def 0 of their own DEX");
        let dexes_of: Vec<u32> = report
            .value()
            .iter()
            .map(|class| class.id().dex().entry_ordinal())
            .collect();
        assert_eq!(dexes_of, [0, 1]);
        assert!(
            report
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code() == DiagnosticCode::DuplicateClassDefinition)
        );
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
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
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
        assert!(
            engine_a
                .references(&artifact, &query, &no_control())
                .is_ok()
        );
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
        assert_eq!(
            runtime.active_bytes.load(Ordering::Relaxed),
            0,
            "nothing retained"
        );
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
            artifact.byte_len()
                + 64
                + artifact
                    .catalog
                    .as_ref()
                    .map(|catalog| {
                        catalog
                            .entries
                            .iter()
                            .map(|entry| 2 * entry.raw_name.len() as u64)
                            .sum::<u64>()
                    })
                    .unwrap_or(0),
            "retained input and catalog bytes are accounted"
        );
        drop(artifact);
        assert_eq!(
            runtime.active_bytes.load(Ordering::Relaxed),
            0,
            "drop releases"
        );
    }

    #[test]
    fn report_permit_follows_report_lifetime_and_releases_for_reuse() {
        let dex = const_string_fixture(1);
        let zip = build_zip(&[("classes.dex", &dex, true)]);
        let probe_engine = Engine::new(EngineOptions::default()).unwrap();
        let probe_artifact = probe_engine
            .open_bytes(Arc::from(zip.clone().into_boxed_slice()), InputKind::Apk, &no_control())
            .unwrap();
        let before_report = probe_engine
            .runtime
            .active_bytes
            .load(Ordering::Relaxed);
        let probe_report = probe_engine
            .archive_entries(
                &probe_artifact,
                &ArchiveEntryQuery::default(),
                &no_control(),
            )
            .unwrap();
        let after_report = probe_engine
            .runtime
            .active_bytes
            .load(Ordering::Relaxed);
        let report_charge = after_report - before_report;
        drop(probe_report);
        drop(probe_artifact);

        let max_engine_owned_bytes = zip.len() as u64
            + 64
            + 2 * b"classes.dex".len() as u64
            + report_charge;
        let engine = Engine::new(EngineOptions {
            limits: Limits {
                max_engine_owned_bytes,
                ..Limits::default()
            },
            ..EngineOptions::default()
        })
        .unwrap();
        let artifact = engine
            .open_bytes(Arc::from(zip.into_boxed_slice()), InputKind::Apk, &no_control())
            .unwrap();
        let report = engine
            .archive_entries(
                &artifact,
                &ArchiveEntryQuery::default(),
                &no_control(),
            )
            .unwrap();
        let report_clone = report.clone();
        assert!(
            std::ptr::eq(report.value(), report_clone.value()),
            "cloning a report must share its charged payload allocation"
        );
        drop(report);
        let error = engine
            .archive_entries(
                &artifact,
                &ArchiveEntryQuery::default(),
                &no_control(),
            )
            .unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ResourceLimit));
        drop(report_clone);
        assert!(engine
            .archive_entries(
                &artifact,
                &ArchiveEntryQuery::default(),
                &no_control(),
            )
            .is_ok());
    }

    #[test]
    fn scanner_working_set_is_reserved_before_rows_and_releases_on_failure() {
        let dex = const_string_fixture(1);
        let zip = build_zip(&[("classes.dex", &dex, true)]);
        let max_engine_owned_bytes = zip.len() as u64 + 64 + 2 * b"classes.dex".len() as u64 + 1;
        let engine = Engine::new(EngineOptions {
            limits: Limits {
                max_engine_owned_bytes,
                ..Limits::default()
            },
            ..EngineOptions::default()
        })
        .unwrap();
        let artifact = engine
            .open_bytes(Arc::from(zip.into_boxed_slice()), InputKind::Apk, &no_control())
            .unwrap();
        let error = engine
            .classes(&artifact, &ClassFilter::none(), &no_control())
            .unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ResourceLimit));
        drop(artifact);
        assert_eq!(
            engine.runtime.active_bytes.load(Ordering::Relaxed),
            0,
            "working-set rejection must release all retained input charges"
        );
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn getclass_pinned_dex_selects_across_entries() {
        // Fixture0 lives in both entries; Fixture1 only in classes2.dex.
        let first = const_string_fixture(1);
        let second = const_string_fixture(2);
        let zip = build_zip(&[
            ("classes.dex", &first, true),
            ("classes2.dex", &second, true),
        ]);
        let path = temp_apk("a07-pin", &zip);
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
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
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
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
        let artifact =
            open_path(&path, &Limits::default(), &test_runtime(), &no_control()).unwrap();
        let error = references(&artifact, &query, &no_control()).unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::MalformedInput);
        fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn backend_normalization_copy_is_admitted_before_allocation() {
        let mut dex = g02_dex();
        dex[8..12].fill(0);
        let probe_engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = probe_engine.open_bytes(Arc::from(dex.clone()), InputKind::Dex, &no_control()).unwrap();
        let (views, integrity) = container::validate_dex_entry(artifact.id(), 0, b"<memory.dex>", &dex, &ControlGuard::new(&no_control()).probe()).unwrap();
        let view = &views.views[0];
        assert_eq!(container::backend_scratch_bytes(view, &integrity), dex.len());
        let work = dex::estimated_scan_work(&dex::DexView::new(views.dex_entry(0), view.bytes()), &artifact.limits.scan).unwrap();
        let max = probe_engine.runtime.active_bytes.load(Ordering::Relaxed) + work + dex.len() as u64 - 1;
        let engine = Engine::new(EngineOptions {
            limits: Limits { max_engine_owned_bytes: max, ..Limits::default() },
            ..EngineOptions::default()
        }).unwrap();
        let artifact = engine.open_bytes(Arc::from(dex), InputKind::Dex, &no_control()).unwrap();
        let baseline = engine.runtime.active_bytes.load(Ordering::Relaxed);
        let error = engine.method_inventory(&artifact, &MethodScope::Root, &no_control()).unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::ResourceLimit);
        assert!(error.to_string().contains("backend normalization scratch"), "{error}");
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), baseline);
        drop(artifact);
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), 0);
        engine.open_bytes(Arc::from(g02_dex()), InputKind::Dex, &no_control()).unwrap();
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn inventory_keeps_previous_dex_work_charged_and_recovers_after_failure() {
        let dex = g02_dex();
        let zip = build_zip(&[("classes.dex", &dex, true), ("classes2.dex", &dex, true)]);
        let probe_engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = probe_engine.open_bytes(Arc::from(zip.clone()), InputKind::Apk, &no_control()).unwrap();
        let scope = MethodScope::Entries(vec![ArchiveEntryId::new(artifact.id(), 0)]);
        let (views, _) = container::validate_dex_entry(artifact.id(), 0, b"classes.dex", &dex, &ControlGuard::new(&no_control()).probe()).unwrap();
        let view = dex::DexView::new(views.dex_entry(0), views.views[0].bytes());
        let work = dex::estimated_scan_work(&view, &artifact.limits.scan).unwrap();
        drop(probe_engine.method_inventory(&artifact, &scope, &no_control()).unwrap());
        let single_peak = probe_engine.runtime.memory.peak.load(Ordering::Relaxed);

        let engine = Engine::new(EngineOptions {
            limits: Limits { max_engine_owned_bytes: single_peak + work / 2, ..Limits::default() },
            ..EngineOptions::default()
        }).unwrap();
        let artifact = engine.open_bytes(Arc::from(zip), InputKind::Apk, &no_control()).unwrap();
        let baseline = engine.runtime.active_bytes.load(Ordering::Relaxed);
        let scope = MethodScope::Entries(vec![ArchiveEntryId::new(artifact.id(), 0)]);
        drop(engine.method_inventory(&artifact, &scope, &no_control()).unwrap());
        let error = engine.method_inventory(&artifact, &MethodScope::Root, &no_control()).unwrap_err();
        assert_eq!(error.kind(), &ErrorKind::ResourceLimit);
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), baseline);
        drop(engine.method_inventory(&artifact, &scope, &no_control()).unwrap());
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), baseline);
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn partial_source_error_clone_retains_one_payload_and_charge() {
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine.open_bytes(Arc::from(g02_dex()), InputKind::Dex, &no_control()).unwrap();
        let inventory = engine.method_inventory(&artifact, &MethodScope::Root, &no_control()).unwrap();
        let target = inventory.value().methods().iter().find(|m| m.has_code()).unwrap().target();
        drop(inventory);
        let report = engine.decompile_method(&artifact, &target, &no_control()).unwrap();
        let source = report.value().clone();
        drop(report);
        let baseline = engine.runtime.active_bytes.load(Ordering::Relaxed);
        let charge = source.owned_bytes() as u64;
        assert!(charge > source.text().len() as u64);
        let memory = reserve_report_memory(&artifact, source.owned_bytes(), &[], "partial-source fixture").unwrap();
        let error = Error::new(ErrorKind::IncompleteDecompilation).with_partial_source(source).with_memory(memory);
        let cloned = error.clone();
        assert!(std::ptr::eq(error.partial_source().unwrap(), cloned.partial_source().unwrap()));
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), baseline + charge);
        drop(error);
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), baseline + charge);
        drop(cloned);
        assert_eq!(engine.runtime.active_bytes.load(Ordering::Relaxed), baseline);
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn method_inventory_keeps_declarations_and_exact_method_target() {
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine
            .open_bytes(Arc::from(g02_dex().into_boxed_slice()), InputKind::Dex, &no_control())
            .unwrap();
        let inventory = engine
            .method_inventory(&artifact, &MethodScope::Root, &no_control())
            .unwrap();
        assert!(!inventory.value().methods().is_empty());
        assert_eq!(inventory.value().dex_entries().len(), 1);
        assert!(inventory.value().fields().iter().any(|field| field.is_static()));
        assert!(inventory
            .value()
            .fields()
            .iter()
            .all(|field| field.id().dex() == inventory.value().dex_entries()[0].id()));
        let declaration = inventory
            .value()
            .methods()
            .iter()
            .find(|method| method.has_code())
            .expect("g02 contains an implemented method");
        let source = engine
            .decompile_method(&artifact, &declaration.target(), &no_control())
            .unwrap();
        assert!(!source.value().text().is_empty());
        assert_eq!(source.value().class().id(), declaration.class_id());
        let other = engine
            .open_bytes(
                Arc::from(const_string_fixture(1).into_boxed_slice()),
                InputKind::Dex,
                &no_control(),
            )
            .unwrap();
        let error = engine
            .decompile_method(&other, &declaration.target(), &no_control())
            .unwrap_err();
        assert_eq!(*error.kind(), ErrorKind::InvalidQuery);
    }

    #[test]
    fn scoped_string_inventory_keeps_unreferenced_pool_rows() {
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine
            .open_bytes(
                Arc::from(const_string_fixture(1).into_boxed_slice()),
                InputKind::Dex,
                &no_control(),
            )
            .unwrap();
        let report = engine
            .strings_in_scope(&artifact, &MethodScope::Root, &no_control())
            .unwrap();
        assert!(!report.value().is_empty());
        assert!(report
            .value()
            .iter()
            .any(|row| row.index() == 0 && row.dex().id().artifact() == artifact.id()));
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn batch_method_visitor_reuses_one_scope_parse() {
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine
            .open_bytes(Arc::from(g02_dex().into_boxed_slice()), InputKind::Dex, &no_control())
            .unwrap();
        let mut declarations = 0usize;
        let mut sources = 0usize;
        engine
            .visit_method_sources(
                &artifact,
                &MethodScope::Root,
                &no_control(),
                |declaration, result| {
                    declarations += 1;
                    assert_eq!(declaration.target().method().dex().artifact(), artifact.id());
                    if let Ok(source) = result {
                        sources += 1;
                        assert_eq!(source.class().id(), declaration.class_id());
                    }
                    Ok(())
                },
            )
            .unwrap();
        assert!(declarations > 0);
        assert!(sources > 0);
    }

    #[cfg(feature = "decompile")]
    #[test]
    fn method_inventory_accepts_nested_dex_scope_and_all_detected() {
        let first = const_string_fixture(1);
        let second = const_string_fixture(2);
        let zip = build_zip(&[
            ("classes.dex", &first, true),
            ("assets/extra.bin", &second, true),
        ]);
        let engine = Engine::new(EngineOptions::default()).unwrap();
        let artifact = engine
            .open_bytes(Arc::from(zip.into_boxed_slice()), InputKind::Apk, &no_control())
            .unwrap();
        let entries = engine
            .archive_entries(&artifact, &ArchiveEntryQuery::default(), &no_control())
            .unwrap();
        let asset = entries
            .value()
            .iter()
            .find(|entry| entry.raw_name() == b"assets/extra.bin")
            .expect("asset DEX is exposed by the archive catalog")
            .id();
        let scoped = engine
            .method_inventory(&artifact, &MethodScope::Entries(vec![asset]), &no_control())
            .unwrap();
        assert!(scoped
            .value()
            .resolved_dexes()
            .iter()
            .all(|dex| dex.entry_ordinal() == asset.ordinal()));
        let classes = engine
            .classes_in_scope(
                &artifact,
                &MethodScope::Entries(vec![asset]),
                &ClassFilter::default(),
                &no_control(),
            )
            .unwrap();
        assert!(classes
            .value()
            .iter()
            .all(|class| class.id().dex().entry_ordinal() == asset.ordinal()));
        let query = query::string_query("Authorization", MatchMode::Literal, &Default::default())
            .unwrap();
        let references = engine
            .references_in_scope(
                &artifact,
                &MethodScope::Entries(vec![asset]),
                &query,
                &no_control(),
            )
            .unwrap();
        assert!(references
            .value()
            .iter()
            .all(|reference| reference.caller().id().dex().entry_ordinal() == asset.ordinal()));
        let selector = ClassSelector::Descriptor(
            ClassDescriptor::from_normalized("LFixture1;".to_owned()).unwrap(),
            None,
        );
        let source = engine
            .decompile_in_scope(
                &artifact,
                &MethodScope::Entries(vec![asset]),
                &selector,
                &no_control(),
            )
            .unwrap();
        assert_eq!(
            source.value().class().id().dex().entry_ordinal(),
            asset.ordinal()
        );
        let all = engine
            .method_inventory(&artifact, &MethodScope::AllDetected, &no_control())
            .unwrap();
        assert_eq!(all.value().resolved_dexes().len(), 2);
        let dexes = engine
            .dexes_in_scope(&artifact, &MethodScope::AllDetected, &no_control())
            .unwrap();
        assert_eq!(dexes.value().len(), 2);
        assert_eq!(
            dexes
                .value()
                .iter()
                .map(|dex| dex.id().entry_ordinal())
                .collect::<Vec<_>>(),
            [0, 1]
        );
        let asset_method = all
            .value()
            .methods()
            .iter()
            .find(|method| method.class_id().dex().entry_ordinal() == asset.ordinal())
            .expect("asset method declaration");
        let asset_source = engine
            .decompile_method(&artifact, &asset_method.target(), &no_control())
            .unwrap();
        assert_eq!(
            asset_source.value().class().id().dex().entry_ordinal(),
            asset.ordinal()
        );
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
    /// Compatibility-visible counter for deterministic tests; all charges are
    /// issued by the single `memory` ledger below.
    #[allow(dead_code)]
    active_bytes: Arc<AtomicU64>,
    /// Single checked ledger used by all engine-owned allocation permits.
    memory: Arc<MemoryAccount>,
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

/// A controlled batch of archive-entry copies. The session holds the
/// engine's operation admission and one decoded-byte account across every
/// `copy_entry` call, so switching entries cannot reset the quota.
pub struct ArchiveCopySession<'engine, 'artifact> {
    artifact: &'artifact Artifact,
    _admission: Admission<'engine>,
    decoded_bytes: AtomicU64,
}

impl<'engine, 'artifact> ArchiveCopySession<'engine, 'artifact> {
    /// Copies one catalog entry to `writer`, returning the decoded byte count.
    /// A failed copy may have written a prefix; callers must discard that
    /// sink before publishing anything.
    pub fn copy_entry<W: Write>(
        &self,
        entry_id: ArchiveEntryId,
        writer: &mut W,
        control: &OperationControl,
    ) -> Result<u64, Error> {
        control.check()?;
        if entry_id.artifact() != self.artifact.id {
            return Err(Error::invalid_query(
                "archive entry belongs to a different artifact",
            ));
        }
        let catalog = self.artifact.catalog.as_ref().ok_or_else(|| {
            Error::new(ErrorKind::UnsupportedFormat)
                .with_context("raw DEX input has no archive entries")
        })?;
        let entry = catalog
            .entries
            .iter()
            .find(|entry| entry.ordinal == entry_id.ordinal())
            .ok_or_else(|| {
                Error::invalid_query(format!(
                    "archive entry ordinal {} does not exist in this artifact",
                    entry_id.ordinal()
                ))
            })?;
        let guard = ControlGuard::new(control);
        zip::read_entry_to(
            &self.artifact.bytes,
            entry,
            &self.artifact.limits.input(),
            &self.decoded_bytes,
            &guard.probe(),
            writer,
        )
    }
}

impl Engine {
    pub fn new(options: EngineOptions) -> Result<Engine, Error> {
        let count = options.threads.unwrap_or(1);
        if count == 0 {
            return Err(Error::invalid_query(
                "worker threads must be greater than zero",
            ));
        }
        let pool = Arc::new(
            rayon::ThreadPoolBuilder::new()
                .num_threads(count)
                .build()
                .map_err(|error| Error::invalid_query(format!("worker pool: {error}")))?,
        );
        let (memory, active_bytes) = MemoryAccount::new(options.limits.max_engine_owned_bytes);
        let runtime = Arc::new(Runtime {
            admission: Mutex::new(()),
            active_bytes,
            memory: Arc::new(memory),
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
            InputKind::Dex => open_dex_bytes(bytes, &self.options.limits, &self.runtime, control),
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

    /// Resolves a DEX scope to logical entries without retaining method or
    /// class declarations. The selected input is still validated before the
    /// report is returned.
    pub fn dexes_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        control: &OperationControl,
    ) -> Result<Report<Vec<DexEntry>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| dexes_in_scope(artifact, scope, control))
    }

    /// Returns every central-directory entry in stable ordinal order. The
    /// result is rejected when either projection bound would be exceeded;
    /// callers never receive a silently truncated catalog.
    pub fn archive_entries(
        &self,
        artifact: &Artifact,
        query: &ArchiveEntryQuery,
        control: &OperationControl,
    ) -> Result<Report<Vec<ArchiveEntryFact>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        let catalog = artifact.catalog.as_ref().ok_or_else(|| {
            Error::new(ErrorKind::UnsupportedFormat)
                .with_context("raw DEX input has no archive entries")
        })?;
        let mut facts = Vec::new();
        let mut result_bytes = 0usize;
        for entry in &catalog.entries {
            control.check()?;
            if facts.len() >= query.max_items {
                return Err(Error::resource_limit(format!(
                    "archive directory exceeds the {} entry projection limit",
                    query.max_items
                )));
            }
            let fact = ArchiveEntryFact::new(
                ArchiveEntryId::new(artifact.id, entry.ordinal),
                entry.raw_name.clone(),
                entry.display(),
                entry.method,
                u64::from(entry.compressed_size),
                u64::from(entry.uncompressed_size),
                entry.crc32,
                entry.flags & 0x0001 != 0,
                entry.directory,
            );
            let added = fact.estimated_bytes();
            result_bytes = result_bytes.checked_add(added).ok_or_else(|| {
                Error::resource_limit("archive entry projection byte count overflow")
            })?;
            if result_bytes > query.max_result_bytes {
                return Err(Error::resource_limit(format!(
                    "archive entry projection reaches {result_bytes} bytes, above the {} result limit",
                    query.max_result_bytes
                )));
            }
            facts.push(fact);
        }
        let result_items = facts.len() as u64;
        let diagnostics = artifact.open_diagnostics.clone();
        let memory = reserve_report_memory(
            artifact,
            result_bytes,
            &diagnostics,
            "archive-entry report",
        )?;
        Ok(Report::new(
            facts,
            diagnostics,
            OperationStats {
                result_items,
                ..Default::default()
            },
        )
        .with_memory(memory))
    }

    /// Starts a batch sharing one decoded-byte quota across entry copies.
    pub fn archive_copy_session<'engine, 'artifact>(
        &'engine self,
        artifact: &'artifact Artifact,
        control: &OperationControl,
    ) -> Result<ArchiveCopySession<'engine, 'artifact>, Error> {
        let admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        if artifact.catalog.is_none() {
            return Err(Error::new(ErrorKind::UnsupportedFormat)
                .with_context("raw DEX input has no archive entries"));
        }
        Ok(ArchiveCopySession {
            artifact,
            _admission: admission,
            decoded_bytes: AtomicU64::new(0),
        })
    }

    /// Copies one archive entry using a fresh single-entry quota account.
    pub fn copy_entry<W: Write>(
        &self,
        artifact: &Artifact,
        entry_id: ArchiveEntryId,
        writer: &mut W,
        control: &OperationControl,
    ) -> Result<u64, Error> {
        let session = self.archive_copy_session(artifact, control)?;
        session.copy_entry(entry_id, writer, control)
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

    /// Lists classes over an explicit DEX scope while preserving their
    /// original artifact and logical-member identities.
    pub fn classes_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        filter: &ClassFilter,
        control: &OperationControl,
    ) -> Result<Report<Vec<Class>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| classes_in_scope(artifact, scope, filter, control))
    }

    /// Finds directly declared superclass/interface edges in root DEXes.
    /// Targets need not be defined locally; no inheritance closure is inferred.
    pub fn class_relations(
        &self,
        artifact: &Artifact,
        query: &ClassRelationQuery,
        control: &OperationControl,
    ) -> Result<Report<Vec<ClassRelation>>, Error> {
        self.class_relations_in_scope(artifact, &MethodScope::Root, query, control)
    }

    /// The explicit-scope form of [`Self::class_relations`]. A successful
    /// report validates all selected declaration relationships, including when
    /// nothing matches, but does not scan unrelated instructions or annotations.
    pub fn class_relations_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        query: &ClassRelationQuery,
        control: &OperationControl,
    ) -> Result<Report<Vec<ClassRelation>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| class_relations_in_scope(artifact, scope, query, control))
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

    /// Scans references over an explicit DEX scope with one shared operation
    /// decode and result budget.
    pub fn references_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        query: &crate::model::ReferenceQuery,
        control: &OperationControl,
    ) -> Result<Report<Vec<crate::model::Reference>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| references_in_scope(artifact, scope, query, control))
    }

    /// Returns every decoded string-pool row in an explicit DEX scope,
    /// including strings that have no code reference.
    pub fn strings_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        control: &OperationControl,
    ) -> Result<Report<Vec<StringDeclaration>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| strings_in_scope(artifact, scope, control))
    }

    /// Returns checked, typed instruction operands over an explicit DEX scope.
    /// The result contains no borrowed bytes and is intended for bounded
    /// adapter-side value propagation (for example `const-string` followed by
    /// `System.loadLibrary`).
    pub fn instructions_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        control: &OperationControl,
    ) -> Result<Report<Vec<InstructionFact>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| instructions_in_scope(artifact, scope, control))
    }

    /// Returns typed instruction facts for selected method identities only.
    /// The archive and DEX scope are still validated, while unselected method
    /// code items are skipped before fact decoding and result accounting.
    pub fn instructions_for_methods_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        methods: &[MethodId],
        control: &OperationControl,
    ) -> Result<Report<Vec<InstructionFact>>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime.pool.install(|| {
            instructions_for_methods_in_scope(artifact, scope, methods, control)
        })
    }

    /// Lists every method declared by the selected DEX scope, including
    /// native/abstract declarations and methods with no reference hits.
    #[cfg(feature = "decompile")]
    pub fn method_inventory(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        control: &OperationControl,
    ) -> Result<Report<MethodInventory>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| method_inventory(artifact, scope, control))
    }

    /// Visits each declared method in deterministic scope order without
    /// retaining a whole-scope inventory.  The callback runs while the
    /// current logical DEX is parsed, so callers can keep only the rows they
    /// need for a bounded query.
    #[cfg(feature = "decompile")]
    pub fn visit_method_declarations<F>(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        control: &OperationControl,
        visitor: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&MethodDeclaration) -> Result<(), Error> + Send,
    {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| visit_method_declarations(artifact, scope, control, visitor))
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
        self.runtime
            .pool
            .install(|| decompile(artifact, selector, control))
    }

    /// Decompiles a class selected from an explicit DEX scope. The class
    /// selector's identity, when pinned, is still checked against that scope.
    #[cfg(feature = "decompile")]
    pub fn decompile_in_scope(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        selector: &ClassSelector,
        control: &OperationControl,
    ) -> Result<Report<Source>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| decompile_with_scope(artifact, scope, selector, control))
    }

    /// Renders exactly one declared method. The class component of the target
    /// disambiguates duplicate class descriptors in one DEX.
    #[cfg(feature = "decompile")]
    pub fn decompile_method(
        &self,
        artifact: &Artifact,
        target: &MethodTarget,
        control: &OperationControl,
    ) -> Result<Report<Source>, Error> {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime
            .pool
            .install(|| decompile_selected_method(artifact, target, control))
    }

    /// Visits selected method sources while parsing and census-building each
    /// logical DEX only once. The visitor must consume each borrowed source or
    /// error before returning; a later method may reuse the backend workspace.
    #[cfg(feature = "decompile")]
    pub fn visit_method_sources<F>(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        control: &OperationControl,
        visitor: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&MethodDeclaration, Result<&Source, &Error>) -> Result<(), Error> + Send,
    {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime.pool.install(|| visit_method_sources(artifact, scope, control, None, visitor))
    }

    /// Visits only the supplied declared method targets. Targets are sorted
    /// for deterministic callbacks; ownership, duplicates and DEX scope are
    /// checked first. Each DEX validates its declarations before callbacks.
    /// Sources are released after each callback, including on callback failure.
    #[cfg(feature = "decompile")]
    pub fn visit_selected_method_sources<F>(
        &self,
        artifact: &Artifact,
        scope: &MethodScope,
        methods: &[MethodTarget],
        control: &OperationControl,
        visitor: F,
    ) -> Result<(), Error>
    where
        F: FnMut(&MethodDeclaration, Result<&Source, &Error>) -> Result<(), Error> + Send,
    {
        let _admission = self.admit(control)?;
        self.check_ownership(artifact)?;
        self.runtime.pool.install(|| visit_method_sources(artifact, scope, control, Some(methods), visitor))
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
    let input_memory = reserve_bytes(runtime, len, limits.max_engine_owned_bytes, "input snapshot")?;
    let roots = vec![Root {
        ordinal: 0,
        raw_name: b"<memory.dex>".to_vec(),
        source: RootSource::Raw,
    }];
    let artifact = Artifact {
        id,
        bytes,
        catalog: None,
        roots,
        runtime: Arc::clone(runtime),
        input_memory,
        catalog_memory: None,
        open_diagnostics: Vec::new(),
        limits: *limits,
    };
    Ok(artifact)
}
