# Contract fixture generators and registry rules

This directory is the fixture registry for the A00-A14 acceptance system
(`openspec/implementation/acceptance.md`). Layout:

- `manifest.json` - the case registry (schema below).
- `inputs/` - committed binary fixtures (small DEX/APK files).
- `expected/` - hand-authored expected facts JSON, one file per active case
  with facts. Expected facts are **never** regenerated from candidate output.
- `corpus/` - real-world corpus registry, owned by the A00 corpus subtask;
  other agents must not write there from this file's perspective.

Rules for later work packages:

- Every acceptance matrix ID needs at least one case; the harness enforces
  this in both directions (no unknown IDs either).
- A case has exactly one owner package. Shared bytes (for example the G02 DEX
  used by A04/A05 vendor regressions) are referenced by path, not copied.
- `status=planned` cases carry `input: null` and `facts_path: null`; they
  register the case id, target `facts_kind`, expected outcome and owner now,
  and the owning package flips them to `active` when the bytes and facts exist.
- `facts_kind=process` cases are active without input bytes: their facts file
  contains a `procedure`/`pass_criteria` pair describing an executable check.
  Some procedures reference the post-A10 package layout; their manifest notes
  say until when they are target commands rather than runnable ones.

## Manifest schema (schema_version 1)

```json
{
  "schema_version": 1,
  "cases": [
    {
      "case_id": "kebab-case unique id",
      "matrix_ids": ["REF-01"],
      "audit_refs": ["G01"],
      "owner_package": "A03",
      "source": {
        "origin": "generated|python-main|fdroid|external|process",
        "license": "...",
        "generator": "<support function> v1",
        "seed": 0,
        "url": null,
        "version": null
      },
      "input": {
        "path": "inputs/xxx.apk",
        "sha256": "64 lowercase hex",
        "size": 123
      },
      "expected": {
        "outcome": "pass|error:<Code>",
        "facts_path": "expected/xxx.json",
        "facts_kind": "references|classes|source|manifest|dex-catalog|process"
      },
      "status": "active|planned",
      "notes": "..."
    }
  ]
}
```

Error codes come from `openspec/implementation/interfaces.md`:
`UnsupportedFormat`, `MalformedInput`, `InvalidQuery`, `NotFound`,
`ResourceLimit`, `Cancelled`, `UnsupportedEncoding`, `IncompleteDecompilation`.

## Generators

All generators live in `tests/support/` and are standard-library only (the
crate deliberately has no serde_json / sha2; new test dependencies require the
integration owner to change Cargo.toml).

| Function | Version | Output | Source of truth |
|---|---|---|---|
| `support::dex::make_dex` | v1 | 432-byte DEX 035, two methods sharing one code_item referencing "token" | byte-exact port of `asc-ref/python-main/tests/dex_fixture.py::make_dex` |
| `support::dex::make_static_field_dex` | v1 | 472-byte DEX 035, FIRST=11/SECOND=22, getSecond() sget | byte-exact port of `dex_fixture.py::make_static_field_dex` |
| `support::dex::make_regex_string_dex` | v1 | 424-byte DEX 035, one method referencing "token" and "tokens" | ASC-owned (G01 extension of the same builder) |
| `support::dex::zero_checksum_header` | v1 | input DEX with checksum (8..12) and SHA-1 signature (12..32) zeroed | derived from `make_dex` (G03) |
| `support::apk::apk_with_single_dex` | v1 | single stored-entry APK (local header + central directory + EOCD, DOS date 1980-01-01) | ASC-owned; verified readable by Python `zipfile` |
| `support::sha::{sha1, sha256, adler32, hex_lower}` | v1 | digests for DEX signing and fixture identity | standard FIPS 180-4 constructions |
| `support::json::parse` | v1 | minimal JSON reader (Int/Float kept distinct) | standard-library recursive descent |
| `support::compare::compare_facts` | v1 | structured fact comparison | semantics below |

### Regenerating inputs

After changing a generator, run:

```sh
ASC_REGEN_FIXTURES=1 cargo +1.93.1 test --locked --test contract_harness \
  regenerate_fixture_inputs_when_explicitly_requested -- --nocapture
```

It rewrites `inputs/` and prints the new sizes/sha256 values; update
`manifest.json` to match (the always-on tests fail until they agree). Python
baseline equality constants in `tests/contract_harness.rs` must never change
without a coordinated baseline change.

### Python baseline provenance

`make_dex` and `make_static_field_dex` outputs are pinned to the Python
baseline by SHA-256 constants in `tests/contract_harness.rs`, precomputed with:

```sh
cd /Users/lordcasser/workspace/asc-ref/python-main/tests && python3 -c \
  "import hashlib; from dex_fixture import make_dex, make_static_field_dex; \
   print(hashlib.sha256(make_dex()).hexdigest()); \
   print(hashlib.sha256(make_static_field_dex()).hexdigest())"
```

The Python checkout is a generation-time reference only. Tests never read it,
and it is not a runtime dependency of anything committed here.

## Facts comparison semantics

`support::compare::compare_facts(expected, actual, ordered)`:

- objects compare key-exactly (missing and unexpected keys are differences);
- **top-level** arrays compare as multisets unless `ordered = true`; the only
  ordered facts kind today is `manifest` (document order is semantic there);
  nested arrays always compare element-by-element in order;
- integers and floats never match each other (`1` differs from `1.0`);
- an empty difference list means agreement.

The harness derives `ordered` from the case's `facts_kind` via
`ORDERED_FACTS_KINDS`. Negative controls (removed reference, edited source
text, flipped input byte) are asserted in `tests/contract_harness.rs` so the
comparator cannot silently degrade into an always-pass check.
