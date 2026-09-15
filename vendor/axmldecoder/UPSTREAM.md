# Upstream provenance — axmldecoder

This directory is a maintained fork used by ASC (see PATCHES.md for the
behavioural deltas). The fork keeps the upstream license files
(LICENSE.APACHE, LICENSE.MIT) and the upstream package identity
(`axmldecoder 0.5.0`, `MIT OR Apache-2.0`).

## Recorded source

| Field | Value |
|---|---|
| Package / version | `axmldecoder 0.5.0` |
| Registry archive URL | https://crates.io/api/v1/crates/axmldecoder/0.5.0/download |
| Archive SHA-256 | `c837020c555ea97afbcc1b9514691de349413a9b054ef6a83bf38ed881fd14a7` |
| Upstream repository | https://github.com/Ayrx/axmldecoder |
| Upstream revision | `349d544f0d5c1b1cccaaf52720e40438af32af32` (from the archive's `.cargo_vcs_info.json`) |
| Imported file-tree hash | `d5a86f596747e5ed3d933d54158c4de3975303feeb5da6e4b474f5c2730450b7` |
| Derived version | asc fork of 0.5.0 (renames to `asc-axmldecoder` land with A13) |

The archive SHA-256 matches both the local registry cache
(`~/.cargo/registry/cache/.../axmldecoder-0.5.0.crate`) and the crates.io
index checksum for `axmldecoder 0.5.0`.

## Reproducing the imported tree hash

The tree hash covers exactly the files imported into this directory before
the rasc patches were applied (the upstream source files, without
`.cargo_vcs_info.json`/`.cargo-ok`/CI files):

```sh
cd "$(cargo metadata --format-version 1 --no-deps >/dev/null 2>&1; echo)" # noop
SRC=$(ls -d ~/.cargo/registry/src/*/axmldecoder-0.5.0)
(cd "$SRC" && for f in Cargo.toml Cargo.toml.orig LICENSE.APACHE LICENSE.MIT \
    README.md src/binaryxml.rs src/lib.rs src/stringpool.rs src/xml.rs; do
  printf '%s  %s\n' "$(shasum -a 256 "$f" | awk '{print $1}')" "$f"
done | LC_ALL=C sort | shasum -a 256)
# -> d5a86f596747e5ed3d933d54158c4de3975303feeb5da6e4b474f5c2730450b7
```

## Rebuilding this fork from upstream

1. Fetch the archive from the URL above and verify its SHA-256.
2. Extract it and confirm the imported tree hash.
3. Apply the patch series recorded in PATCHES.md (AX-P01..AX-P04); each entry
   names the files and the behavioural tests that pin it (the vendor crate's
   `src/tests.rs` plus the ASC contract tests in
   `tests/contract_manifest.rs`).
