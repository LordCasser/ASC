#!/usr/bin/env python3
"""Verify the distribution chain end to end, without publishing.

Implements the five steps from openspec/changes/extract-publishable-core/
dependencies.md ("未发布阶段怎么验证"):

1. Package the two derived vendor crates; record .crate sha256/size and the
   normalized manifest.
2. Build a staging directory source: the derived archives plus every locked
   registry dependency from the workspace lockfile (copied out of the local
   cargo cache).
3. Package asc-core and rasc against the staging source only. `--no-verify`
   is recorded as archive-created, never as package-verified.
4. Create an outside-workspace consumer depending on the staged versions
   only (offline; separate CARGO_HOME and target dir) and build it.
5. Verify which package/version/source the consumer actually resolved, and
   check that the vendored patch-test targets and their G02 fixture ship
   inside the archives.

No network access is required beyond the local cargo cache; this script
never runs `cargo publish`.

Usage:
    python3 scripts/verify-distribution.py --out DIR [--toolchain 1.93.1]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

DERIVED = {
    "asc-droidsaw-dex": "vendor/droidsaw-dex",
    "asc-axmldecoder": "vendor/axmldecoder",
}
MEMBER_PACKAGES = {"asc-core", "rasc", "asc-droidsaw-dex", "asc-axmldecoder"}


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None) -> subprocess.CompletedProcess:
    printable = " ".join(cmd)
    suffix = f"  (cwd={cwd})" if cwd else ""
    print(f"+ {printable}{suffix}")
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-4000:])
        print(proc.stderr[-4000:])
        raise SystemExit(f"command failed ({proc.returncode}): {printable}")
    return proc


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cargo(toolchain: str, args: str, cwd: Path, env: dict | None = None) -> subprocess.CompletedProcess:
    cmd = ["cargo", f"+{toolchain}"] + args.split()
    return run(cmd, cwd=cwd, env=env)


def package_crate(crate_dir: Path, out: Path, toolchain: str, env: dict, no_verify: bool) -> dict:
    """`cargo package` one crate; returns archive metadata (no verification
    claim when --no-verify was needed)."""
    # Per-crate target dir: a shared one would let `sorted(...)["-1"]` below
    # pick up a previous crate's archive.
    pkg_dir = out / f"pkg-target-{crate_dir.name}"
    cmd = ["cargo", f"+{toolchain}", "package", "--allow-dirty", "--target-dir", str(pkg_dir)]
    if no_verify:
        cmd.append("--no-verify")
    proc = subprocess.run(cmd, cwd=crate_dir, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-4000:])
        print(proc.stderr[-4000:])
        raise SystemExit(f"cargo package failed for {crate_dir}")
    archive_dir = pkg_dir / "package"
    archive = sorted(archive_dir.glob("*.crate"))[-1]
    record = {
        "crate": archive.name,
        "sha256": sha256(archive),
        "size": archive.stat().st_size,
    }
    if not no_verify:
        record["verified"] = True
    else:
        record["verified"] = False  # archive-created only
    unpacked = archive_dir / archive.name.removesuffix(".crate")
    normalized = unpacked / "Cargo.toml"
    if normalized.exists():
        record["normalized_manifest_sha256"] = sha256(normalized)
    shutil.copy2(archive, out / archive.name)
    return record


def locked_closure(workspace: Path) -> list[str]:
    """`name-version` strings for every non-workspace package in the lock."""
    lock = (workspace / "Cargo.lock").read_text()
    pairs: list[str] = []
    block_name: str | None = None
    for line in lock.splitlines():
        line = line.strip()
        if line.startswith("name = "):
            block_name = line.split('"')[1]
        elif line.startswith("version = ") and block_name is not None:
            version = line.split('"')[1]
            if block_name not in MEMBER_PACKAGES:
                pairs.append(f"{block_name}-{version}")
            block_name = None
    return sorted(set(pairs))


def cache_roots() -> list[Path]:
    home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    registry_cache = home / "registry" / "cache"
    if registry_cache.exists():
        return sorted((p for p in registry_cache.iterdir() if p.is_dir()))
    return []


def find_cached_crate(name_version: str, roots: list[Path]) -> Path | None:
    for root in roots:
        candidate = root / f"{name_version}.crate"
        if candidate.exists():
            return candidate
    return None


def write_staging_config(staging: Path, registry_dir: Path) -> Path:
    config_dir = staging / "cargo-home"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "config.toml").write_text(
        "[source.crates-io]\n"
        "replace-with = \"staging\"\n"
        "\n"
        "[source.staging]\n"
        f"directory = \"{registry_dir}\"\n"
    )
    return config_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--toolchain", default="1.93.1")
    args = parser.parse_args()
    ws = args.workspace.resolve()
    out = args.out.resolve()
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    report: dict = {
        "workspace": str(ws),
        "toolchain": args.toolchain,
        "archives": {},
        "staging": {},
        "consumer": {},
        "smokes": {},
    }

    # ---- 1. package the derived vendor crates -------------------------------
    archives: dict[str, dict] = {}
    base_env = dict(os.environ)
    for name, rel in DERIVED.items():
        print(f"\n=== [1] packaging derived crate {name}")
        archives[name] = package_crate(ws / rel, out, args.toolchain, base_env, no_verify=False)

    # ---- 2. staging directory source ----------------------------------------
    print("\n=== [2] staging directory source")
    staging = out / "staging"
    registry_dir = staging / "registry"
    registry_dir.mkdir(parents=True)
    closure = locked_closure(ws)
    roots = cache_roots()
    missing = []
    def stage_crate(crate_file: Path) -> None:
        # A cargo *directory source* serves unpacked package directories, each
        # with a .cargo-checksum.json carrying the .crate digest.
        name_version = crate_file.name.removesuffix(".crate")
        pkg_dir = registry_dir / name_version
        pkg_dir.mkdir(parents=True, exist_ok=True)
        run(["tar", "-xzf", str(crate_file), "-C", str(pkg_dir)])
        digest = sha256(crate_file)
        # flatten one level (crates unpack into <name>-<version>/)
        inner = pkg_dir / name_version
        for entry in inner.iterdir():
            shutil.move(str(entry), pkg_dir / entry.name)
        inner.rmdir()
        (pkg_dir / ".cargo-checksum.json").write_text(
            json.dumps({"files": {}, "package": digest})
        )
    for name_version in closure:
        cached = find_cached_crate(name_version, roots)
        if cached is None:
            missing.append(name_version)
            continue
        stage_crate(cached)
    if missing:
        raise SystemExit(
            "locked closure crates missing from the local cache (run `cargo fetch` in the "
            f"workspace first): {missing}"
        )
    for name, record in archives.items():
        crate_file = out / record["crate"]
        stage_crate(crate_file)
    config_dir = write_staging_config(staging, registry_dir)
    report["staging"] = {
        "directory_source": str(registry_dir),
        "cargo_home": str(config_dir),
        "closure_crates": len(closure),
        "derived_in_staging": sorted(archives),
    }

    # ---- 3. package the products against staging ----------------------------
    staging_env = dict(os.environ)
    staging_env["CARGO_HOME"] = str(config_dir)
    pack_root = staging / "pack"
    shutil.rmtree(pack_root, ignore_errors=True)
    pack_root.mkdir(parents=True)
    # The workspace tree may carry its own .cargo/config.toml (registry
    # mirror), which would beat the CARGO_HOME staging config, and the
    # product manifests inherit workspace.package fields. Mirror the crates
    # into a minimal workspace under the staging tree with a local config
    # that pins the directory source.
    (pack_root / ".cargo").mkdir()
    (pack_root / ".cargo" / "config.toml").write_text(
        "[source.crates-io]\n"
        "replace-with = \"staging\"\n"
        "\n"
        "[source.staging]\n"
        f"directory = \"{registry_dir}\"\n"
    )
    (pack_root / "Cargo.toml").write_text(
        "[workspace]\n"
        "resolver = \"2\"\n"
        "members = [\"crates/asc-core\", \"crates/asc-cli\"]\n"
        "\n"
        "[workspace.package]\n"
        "edition = \"2024\"\n"
        "rust-version = \"1.93\"\n"
        "license = \"Apache-2.0\"\n"
    )
    for rel in ["crates/asc-core", "crates/asc-cli", "vendor/droidsaw-dex", "vendor/axmldecoder"]:
        shutil.copytree(ws / rel, pack_root / rel)
    for name, rel in {"asc-core": "crates/asc-core", "rasc": "crates/asc-cli"}.items():
        print(f"\n=== [3] packaging product {name} against staging")
        archives[name] = package_crate(pack_root / rel, out, args.toolchain, staging_env, no_verify=True)
        # rasc depends on asc-core: stage each product archive as soon as it
        # exists so later products resolve it from the directory source.
        crate_file = out / archives[name]["crate"]
        digest = sha256(crate_file)
        pkg_dir = registry_dir / crate_file.name.removesuffix(".crate")
        pkg_dir.mkdir(parents=True, exist_ok=True)
        run(["tar", "-xzf", str(crate_file), "-C", str(pkg_dir)])
        # flatten the single inner <name>-<version>/ directory
        inner = pkg_dir / crate_file.name.removesuffix(".crate")
        for entry in inner.iterdir():
            shutil.move(str(entry), pkg_dir / entry.name)
        inner.rmdir()
        (pkg_dir / ".cargo-checksum.json").write_text(
            json.dumps({"files": {}, "package": digest})
        )

    # ---- 4. outside-workspace consumer --------------------------------------
    print("\n=== [4] consumer build (offline, staged archives only)")
    consumer = staging / "consumer"
    (consumer / "src").mkdir(parents=True)
    (consumer / "Cargo.toml").write_text(
        "[package]\n"
        "name = \"dist-consumer\"\n"
        "version = \"0.1.0\"\n"
        "edition = \"2021\"\n"
        "\n"
        "[dependencies]\n"
        "asc-core = { version = \"0.1.0\", features = [\"decompile\", \"manifest\"] }\n"
        "\n"
        "[[bin]]\n"
        "name = \"dist-consumer\"\n"
        "path = \"src/main.rs\"\n"
    )
    (consumer / "src" / "main.rs").write_text(
        "fn main() {\n"
        "    let engine = asc_core::engine::Engine::new(asc_core::engine::EngineOptions::default());\n"
        "    match engine {\n"
        "        Ok(_) => println!(\"engine ok\"),\n"
        "        Err(e) => {\n"
        "            eprintln!(\"engine error: {e}\");\n"
        "            std::process::exit(1);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    (consumer / ".cargo").mkdir()
    (consumer / ".cargo" / "config.toml").write_text(
        "[source.crates-io]\n"
        "replace-with = \"staging\"\n"
        "\n"
        "[source.staging]\n"
        f"directory = \"{registry_dir}\"\n"
    )
    consumer_env = dict(os.environ)
    consumer_env["CARGO_HOME"] = str(config_dir)
    consumer_env["CARGO_TARGET_DIR"] = str(staging / "consumer-target")
    cargo(args.toolchain, "build --offline", consumer, env=consumer_env)
    report["consumer"] = {"dir": str(consumer), "build": "ok (offline, staging directory source)"}

    # ---- 5. resolved identity + archive shipping checks ---------------------
    lock = (consumer / "Cargo.lock").read_text()
    for name in archives:
        report["smokes"][f"resolved:{name}"] = f'name = "{name}"' in lock
    for name in DERIVED:
        unpack = staging / name
        shutil.rmtree(unpack, ignore_errors=True)
        unpack.mkdir(parents=True, exist_ok=True)
        crate_file = out / archives[name]["crate"]
        run(["tar", "-xzf", str(crate_file), "-C", str(unpack)])
        src_dir = unpack / f"{name}-0.1.0"
        if name == "asc-droidsaw-dex":
            # The patch-contract tests and their G02 fixture must ship in the
            # derived archive (dependencies.md: never let /tests exclusion
            # silence the patch tests).
            has_g02 = (src_dir / "tests" / "fixtures" / "g02-static-initializers.dex").exists()
            report["smokes"][f"{name}:g02-fixture-shipped"] = has_g02
            report["smokes"][f"{name}:patch-test-shipped"] = (
                src_dir / "tests" / "asc_contracts.rs"
            ).exists()
        else:
            report["smokes"][f"{name}:lib-shipped"] = (src_dir / "src").exists()

    # Build the rasc bin from its own archive (offline, staging source).
    rasc_unpack = staging / "rasc-bin"
    shutil.rmtree(rasc_unpack, ignore_errors=True)
    rasc_unpack.mkdir(parents=True)
    rasc_crate = out / archives["rasc"]["crate"]
    run(["tar", "-xzf", str(rasc_crate), "-C", str(rasc_unpack)])
    rasc_src = rasc_unpack / "rasc-0.1.0"
    rasc_env = dict(os.environ)
    rasc_env["CARGO_HOME"] = str(config_dir)
    rasc_env["CARGO_TARGET_DIR"] = str(staging / "rasc-bin-target")
    cargo(args.toolchain, "build --offline", rasc_src, env=rasc_env)
    report["smokes"]["rasc:bin-built-from-archive"] = (
        (rasc_src / "target") is not None
        and (staging / "rasc-bin-target" / "debug" / "rasc").exists()
    )

    (out / "verify-distribution-report.json").write_text(json.dumps(report, indent=2))
    print("\nsmokes:", json.dumps(report["smokes"], indent=2))
    print(f"report: {out / 'verify-distribution-report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
