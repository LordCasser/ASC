"""Read-only parity probes; run with the Python baseline's interpreter.

Usage: python reproduce.py --python-root CHECKOUT --rust-bin BINARY --output JSON
This is audit tooling, not the proposed implementation or an exhaustive parity gate.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import warnings
import zipfile
import zlib
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-root", type=Path, required=True)
    parser.add_argument("--rust-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.python_root.resolve()
    binary = args.rust_bin.resolve()
    sys.path[:0] = [str(root), str(root / "tests")]
    from dex_fixture import make_dex, make_static_field_dex

    def run(command):
        proc = subprocess.run(command, cwd=root, capture_output=True, timeout=60)
        return {
            "exit": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", "replace"),
            "stderr": proc.stderr.decode("utf-8", "replace"),
        }

    cases = []
    with tempfile.TemporaryDirectory(prefix="asc-parity-") as directory:
        scratch = Path(directory)

        def archive(name, entries, compression=zipfile.ZIP_STORED):
            path = scratch / (name + ".apk")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w", compression=compression) as z:
                    for entry, data in entries:
                        z.writestr(entry, data)
            return path

        def repair(data):
            data = bytearray(data)
            data[12:32] = hashlib.sha1(data[32:]).digest()
            struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
            return bytes(data)

        def probe(name, argv):
            py = run([sys.executable, str(root / "main.py"), *map(str, argv)])
            rs = run([str(binary), *map(str, argv)])
            # Compare multisets (not sets); ordering is separately observable.
            record = {
                "id": name,
                "args": [str(a).replace(str(scratch), "<fixture>") for a in argv],
                "same_exit": py["exit"] == rs["exit"],
                "same_stdout": py["stdout"] == rs["stdout"],
                "same_line_multiset": sorted(py["stdout"].splitlines()) == sorted(rs["stdout"].splitlines()),
            }
            for label, result in (("python", py), ("rust", rs)):
                for stream in ("stdout", "stderr"):
                    content = result[stream]
                    result[stream + "_sha256"] = hashlib.sha256(content.encode()).hexdigest()
                    result[stream + "_lines"] = len(content.splitlines())
                    result[stream] = content[:3000].replace(str(scratch), "<fixture>").replace(str(root), "<python-root>")
                    result[stream + "_truncated"] = len(content) > 3000
                record[label] = result
            cases.append(record)

        data = make_dex()
        stored = archive("stored", [("classes.dex", data), ("classes2.dex", data)])
        deflated = archive("deflated", [("classes.dex", data), ("classes2.dex", data)], zipfile.ZIP_DEFLATED)
        for name, path in (("stored", stored), ("deflated", deflated)):
            probe(name + "-string", ["findrefs", "--threads", "2", path, "string", "token"])
            probe(name + "-getclass", ["getclass", "--threads", "2", path, "example.Test"])
        for query, name in (("tok.n", "wildcard"), ("tok(en|x)", "alternation"), ("[", "invalid-regex"), ("", "empty")):
            probe("string-" + name, ["findrefs", "--threads", "1", stored, "string", query])
        for suffix, options in (("unscoped", []), ("exact-class", ["--class", "example.Statics"]), ("fuzzy-class", ["--class", "Lexample/Stat.cs;", "--fuzzy-class"])):
            path = archive("statics", [("classes.dex", make_static_field_dex())])
            probe("field-regex-" + suffix, ["findrefs", "--threads", "1", path, "field", "SEC.ND", *options])
        probe("static-values-source", ["getclass", "--threads", "1", path, "example.Statics"])
        probe("missing-class", ["getclass", stored, "example.Absent"])
        probe("no-arguments", [])
        probe("zero-workers", ["findrefs", "--threads", "0", stored, "string", "token"])
        probe("negative-workers", ["findrefs", "--threads", "-1", stored, "string", "token"])
        probe("debug-stream", ["findrefs", "--debug", "--threads", "1", stored, "string", "token"])
        duplicate = archive("duplicate-fallback", [("a.dex", data), ("a.dex", data)])
        probe("duplicate-fallback", ["findrefs", "--threads", "1", duplicate, "string", "token"])
        damaged = bytearray(data)
        damaged[8:32] = bytes(24)
        path = archive("zero-checksum", [("classes.dex", damaged)])
        probe("zero-checksum-getclass", ["getclass", "--threads", "1", path, "example.Test"])
        # Keep instruction width fixed: const v0, 0x0005001a contains fake
        # const-string opcode/index bytes inside its 32-bit immediate.
        fake = bytearray(data)
        instruction = fake.index(b"\x1a\0\x05\0\x0e\0")
        fake[instruction:instruction + 6] = b"\x14\0\x1a\0\x05\0"
        path = archive("operand-false-positive", [("classes.dex", repair(fake))])
        probe("operand-false-positive", ["findrefs", "--threads", "1", path, "string", "token"])
        typed = bytearray(data)
        typed[instruction:instruction + 6] = b"\x1c\0\0\0\x0e\0"
        path = archive("type", [("classes.dex", repair(typed))])
        for query in ("example/Test", "example.Test", "Lexample/T.st;"):
            probe("type-" + query, ["findrefs", "--threads", "1", path, "type", query])
        # The supplied real DEX provides representative member/metadata output.
        corpus = root / "tests/fixtures/reference-workload.zip"
        with zipfile.ZipFile(corpus) as z:
            real_data = z.read("classes.dex")
        path = archive("reference-workload", [("classes.dex", real_data)])
        for kind, query in (("string", "Authorization"), ("method", "onCreate"), ("field", "INSTANCE"), ("type", "Activity")):
            probe("corpus-" + kind, ["findrefs", "--threads", "2", path, kind, query])
        probe("corpus-getclass", ["getclass", "--threads", "2", path, "com.google.android.material.timepicker.ClockFaceView"])

    result = {
        "python_baseline": "ccc6bae7704f5c5ef1a7271e27314837079621fb",
        "rust_baseline": "e809c7b4b454ebc8eb4467f56d44a82e6139472b",
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "androguard_available": importlib.util.find_spec("androguard") is not None,
        "real_dex_sha256": hashlib.sha256(real_data).hexdigest(),
        "python_source_sha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in ("main.py", "requirements.txt", "tests/dex_fixture.py", "src/asc_client/apk_handler.py", "src/asc_client/asc_handler.py")
        },
        "rust_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "note": "Finite probes; a difference is an observation, not automatically a regression. Source output is not a semantic equivalence proof.",
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    for case in cases:
        print(case["id"], "exit", case["python"]["exit"], case["rust"]["exit"], "rows", case["python"]["stdout_lines"], case["rust"]["stdout_lines"], "multiset", case["same_line_multiset"])


if __name__ == "__main__":
    main()
