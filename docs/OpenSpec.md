# Droid ASC - Rust Rewrite Specification (OpenSpec)

## 1. Problem Statement
The current Droid ASC is a fast APK analysis and decompilation engine written in Python. It bypasses full deflate operations, builds on-the-fly Huffman tables, and utilizes deterministic constant relocation of the R8 compiler to perform lightning-fast cross-DEX code searches and on-demand DEX rebuilding. However, Python has inherent limitations with the GIL, execution speed, and memory management overhead. 
A complete rewrite in Rust aims to maximize performance (especially multi-threading over Deflate streams and large binary buffers), ensure memory safety, reduce runtime dependencies (like tkinter, androguard patching), and provide a single statically compiled executable.

## 2. Goals & Non-Goals

### Goals
- **Full Rust rewrite**: Port all existing features (`getclass`, `findrefs`, GUI) to Rust.
- **Performance**: Exceed Python's speed via zero-copy binary parsing, Rayon-based multi-threading, and efficient memory utilization.
- **DEX Engine**: Implement `tinydex`, `dex_manager` (DEX rebuilding/hollowing), and `findrefs` natively in Rust.
- **Decompiler**: Initially integrate a lightweight native decompiler for small rebuilt DEX files (or call out to Jadx/Androguard minimally if native translation takes too long, though a native minimalist Dalvik-to-Java AST module is the ultimate goal).
- **GUI**: Replace `tkinter` with a modern, performant Rust GUI framework (e.g., `egui` or `iced`).

### Non-Goals
- Building a full-blown generalized decompiler (like Ghidra or IDA) — ASC focuses on targeted fast extraction and minimal decompilation.
- Modifying the original APK (ASC is a read-only analysis tool).

## 3. Architecture & Components

### 3.1 APK Handler (`apk_handler`)
- **Direct Zip Parsing**: Read Central Directory from end of mmap'ed APK.
- **Deflate Streaming**: Probe and decompress chunks on-the-fly directly to memory (bypassing file writes).
- **Concurrency**: Use `rayon` for parallel extraction and searching.

### 3.2 DEX Engine (`tinydex`, `dex_manager`)
- **Parser**: Zero-copy parsing over mmap buffers. Parse strings, types, fields, methods, classes.
- **Constructor & Remapper**: Given a target class, resolve dependencies, hollow out unneeded data, remap IDs, and output a valid, minimal `.dex` buffer in memory.

### 3.3 Reference Search (`findrefs`)
- O(1) & O(log N) locators for Strings, Types, Fields, and Methods across DEX files.
- DVM interpreter/scanner to trace `pc` bounds and identify accurate bytecode references.

### 3.4 Decompiler
- Translates the minimal in-memory DEX bytes into Java source code.
- To handle the objective "完全迁移到rust", we must develop or embed a Dalvik bytecode to Java/Smali representation in Rust. 

### 3.5 Client & GUI
- **CLI Mode**: Argument parsing via `clap`.
- **GUI Mode**: Built on `egui` (recommended for fast iteration and native feeling), including source code editor, reference lists, and theme management.

## 4. Phase Breakdown & Subagent Plan

### Phase 1: Foundation & CLI Bootstrapping (Current)
- Setup Cargo project.
- Implement CLI parsing (`clap`).
- Implement basic `mmap` APK handler and CD parser.

### Phase 2: Core DEX Engine (Parallelizable)
- `tinydex`: DEX header, structures, and zero-copy parser. -> **Subagent Task**
- `findrefs` locators (Binary search over DEX sections). -> **Subagent Task**

### Phase 3: DEX Rebuilder (Parallelizable)
- Implement `dex_remapper`, `dex_constructor`, and `dex_builder`. -> **Subagent Task**
- DVM instruction scanner (`dvm_interpreter` port). -> **Subagent Task**

### Phase 4: Decompiler & GUI
- Minimal Decompiler core in Rust.
- Rust GUI implementation using `egui` (Porting the `tkinter` logic).

## 5. Review & Execution
After review, we will create a new branch, initialize `cargo init`, and delegate independent tasks to the `proxy/gemini-3.8-flash-high` subagent.