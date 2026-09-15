# rasc patches to axmldecoder 0.5.0

This is a vendored fork of `axmldecoder 0.5.0` (MIT OR Apache-2.0; upstream
provenance in UPSTREAM.md). Every behavioural difference against the upstream
archive is registered below with a stable AX-P id. Changes are marked
`PATCHED (rasc)` in the source where they are localised.

The fork's charter (openspec change `maintain-patched-analysis-backends`,
design §5) is an explicit data path: bytes in, a bounded ordered document
model out — raw typed values, string styles, resource ids, namespace scopes,
node order. Formatting typed values into readable strings is **not** done in
this crate; the raw `type`/`data` pair is the single source of truth and the
projection lives in the ASC core (`src/manifest.rs`).

## Patch ledger

### AX-P01 — extended string lengths (stringpool)

* Problem input: manifests whose string pool uses the two-byte UTF-8 length
  forms or the extended UTF-16 length form (>= 32768 units). Upstream
  `unimplemented!()` aborted on them; a real corpus APK (a repacked Douyin
  build) carries one.
* Files/symbols: `src/stringpool.rs` (replaces the deku reader);
  `src/cursor.rs` (bounds-checked reads).
* Target behaviour: both length forms decode; every read is bounds-checked
  against the pool chunk; declared lengths may not cross the chunk end;
  per-string unit limits are enforced before allocation.
* Tests: vendor `extended_lengths_decode_in_both_pool_encodings`; ASC
  MAN-01 fixtures with long UTF-8/UTF-16 strings.
* Supersedes historical patch items 1 and 2 (see the mapping below).
* Necessary: yes. Upstream panics on real-world input.
* Removal condition: an upstream release implements both length forms with
  bounds checks.

### AX-P02 — structural integrity and complete consumption (binaryxml)

* Problem input: documents with unmatched end elements / end namespaces,
  duplicate attributes, string indices outside the pool, a second root,
  structural garbage after the single root, declared sizes that do not match
  the input, unknown node chunk types, or oversized depth/node/attribute
  counts. Upstream ignored end namespaces entirely, returned success at the
  first root close (leaving the rest of the node stream unread), and reached
  `unwrap`s that abort the process on truncated input (the release profile
  uses `panic = "abort"`).
* Files/symbols: `src/binaryxml.rs` (complete rewrite of the stream walk),
  `src/cursor.rs`.
* Target behaviour: start/end elements match by their raw string indices;
  end namespaces match the innermost open start; exactly one root; the whole
  declared document length is consumed before success; duplicate attributes
  are rejected; depth 256 / nodes 1e6 / attributes 1e6 limits return
  `ParseError::Limit`; no panic path exists on any input.
* Tests: vendor tests `a_second_root_is_rejected`,
  `structural_garbage_after_the_root_is_rejected`,
  `an_unmatched_end_element_is_rejected`,
  `an_unmatched_end_namespace_is_rejected`,
  `duplicate_attributes_are_rejected`, `cdata_outside_any_element_is_rejected`,
  `a_document_without_a_root_is_rejected`,
  `string_indices_outside_the_pool_are_rejected`,
  `unknown_node_chunk_types_are_rejected`, `limits_are_enforced`,
  `mutation_smoke_never_panics`; ASC MAN-04 fixtures.
* Supersedes historical patch items 3 and 4.
* Necessary: yes.
* Removal condition: upstream validates all of the above.

### AX-P03 — raw typed values, unknown types, exact complex math (binaryxml)

* Problem input: typed values whose type byte is outside the named set
  (0x07/0x08 dynamic references, reserved 0x13-0x1B, >= 0x20) used to fail
  the whole document; dimensions/fractions were formatted through
  seven-digit-rounded radix multiples, shifting large mantissas; colours were
  stringified as decimals.
* Files/symbols: `src/binaryxml.rs` (`RawValue` keeps `type_byte`/`data`
  verbatim); the readable projection with exact powers of two
  (2^-8/2^-15/2^-23/2^-31) and the `<0x.., type 0x..>` fallback now lives in
  the ASC core `src/manifest.rs::TypedValue::format` — the behaviour is
  preserved, the location moved so the vendor never formats.
* Tests: vendor `unknown_raw_type_bytes_survives`; ASC MAN-02 fixture matrix
  (all typed values incl. raw float bits, dimensions/fractions, the four
  colour forms, unknown/reserved/dynamic types).
* Supersedes historical patch items 5, 6, 7 and 8.
* Necessary: yes (a single unlisted type byte must not fail a real manifest,
  and precision must not drift).
* Removal condition: upstream exposes raw values (or exact formatting) with
  the same guarantees.

### AX-P04 — ordered document model with scopes, styles and resource ids

* Problem input/output: upstream folded the document into a formatted
  `IndexMap<String, String>` per element, dropping node order, CDATA
  positions, comments, namespace scopes, prefix shadowing, string styles and
  resource ids; `XmlDocument::new` also pre-seeded the android namespace
  unconditionally and ignored end namespaces.
* Files/symbols: `src/binaryxml.rs` (`Document`/`Element`/`Node`/`Cdata`/
  `Attribute`/`NamespaceEvent`), `src/stringpool.rs` (`StringPoolData` with
  style spans), `src/xml.rs` (the framework attribute-name table).
* Target behaviour: the parser returns an ordered, `Send` model (no `Rc`)
  — nodes in stream order, attributes with URI/name/raw string/typed value,
  namespace events attached to the element whose scope they open, string
  styles as validated metadata, the resource map verbatim, and AXML
  comments/line numbers on the node metadata. The android-namespace
  inference (declaration missing but URI confirmable) is a core-layer
  decision reported as a warning diagnostic, not a vendor-side silent
  default.
* Tests: vendor `reads_back_the_ordered_tree`, `style_spans_survive_as_metadata`,
  `prefix_shadowing_attends_to_scopes`, `element_namespaces_resolve_through_the_pool`,
  `parses_without_a_resource_map`; ASC MAN-01/MAN-03 fixtures.
* Necessary: yes (the lossless manifest contract requires the data).
* Removal condition: upstream ships an equivalent ordered model.

## Mapping of the historical patch list (1-8)

The previous PATCHES.md enumerated eight fixes against upstream 0.5.0. They
are all still in force; the ledger above re-homes them:

| Historical item | Now |
|---|---|
| 1. UTF-16 extended two-byte length | AX-P01 |
| 2. UTF-8 two-byte length forms | AX-P01 |
| 3. stray end element -> parse error | AX-P02 |
| 4. CDATA outside any element -> parse error | AX-P02 |
| 5. typed-value formatting (refs, signed ints, hex, floats, dimensions, fractions, colours, booleans, fallback) | AX-P03 (projection moved to core `src/manifest.rs`) |
| 6. raw type byte + fallback for unlisted types | AX-P03 |
| 7. exact powers of two for radix multiples | AX-P03 |
| 8. colour types 0x1C-0x1F unified, 0x13-0x1B stay on the fallback | AX-P03 |

## Notes on the rewrite shape

Upstream parsed with deku-derived readers whose counts and sizes came
straight from attacker-controlled headers, with `unwrap`s and one `assert!`
on the path (`style_count == 0` — styled pools aborted the process). The
fork replaces the deku readers with a validating cursor parser
(`src/cursor.rs`) and keeps style pools instead of rejecting them. The
declared dependency list of the crate is unchanged so the ASC workspace
lockfile stays untouched; `deku`/`indexmap`/`byteorder` are no longer
referenced by the sources and can be dropped when the packaging work
(A13) rewrites the manifest.
