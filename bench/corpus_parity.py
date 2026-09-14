"""Parity check of rasc against the original Python ASC for any APK.

Compares, per APK:
  * the class-definition set (`rasc classes` vs the reference's GuiDexStore
    list),
  * the row multiset of every query (`rasc findrefs ...` vs `main.py findrefs`)
    - bidirectionally: a row occurrence (identity plus matched text) that
    either side reports and the other misses is a failure,
  * the decoded manifest as a tree (tag names, attributes, and the normalized
    text/tail of every node). Renderer whitespace is normalized away - we emit
    an XML declaration and four-space indentation, the reference emits
    neither - but any non-whitespace text/tail or attribute difference is a
    failure.

A difference can be exempted only row-precisely, in bench/parity_allowlist.json
(one APK sha256, one query, one row identity per entry, each with a reason
citing audit findings or bench/row_oracle.py evidence). There is no way to
exempt a whole query, APK or side, and an exemption that no run ever hits is
itself a failure, so stale entries break the gate instead of silently
narrowing it. Manifest differences cannot be exempted.

Usage:
    RASC_BIN=target/release/rasc \
    REF_ROOT=/path/to/reference \
    REF_PY=/path/to/python \
    python3 bench/corpus_parity.py app.apk [more.apk ...]

    python3 bench/corpus_parity.py --self-test

The self-test runs the comparators on built-in tampered samples; it needs no
APK, no reference checkout and no rasc binary. The APK mode exits non-zero
when any check fails, so it doubles as a gate for new corpus APKs and needs
the reference checkout plus its Python environment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from collections import Counter

QUERIES = ["string androidx", "string Authorization"]
DRIVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reference_scenario.py")
ROOT = os.path.dirname(os.path.dirname(DRIVER))
ALLOWLIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "parity_allowlist.json")


def run(command: list[str], cwd: str | None = None, env: dict[str, str] | None = None) -> str:
    proc = subprocess.run(command, capture_output=True, text=True, cwd=cwd, env=env)
    if proc.returncode != 0:
        raise SystemExit(f"command failed ({proc.returncode}): {' '.join(command)}\n{proc.stderr.strip()[:400]}")
    return proc.stdout


def asc_environment() -> dict[str, str]:
    return dict(os.environ, REF_ROOT=os.environ["REF_ROOT"])


def to_java_name(name: str) -> str:
    """Both sides hand out `Lpkg/Name;`; compare dotted names."""
    name = name.strip()
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rasc_classes(binary: str, apk: str) -> set[str]:
    out = run([binary, "classes", "--threads", "8", apk])
    return {to_java_name(line.split(" | ")[1]) for line in out.splitlines() if line.strip()}


def asc_classes(apk: str) -> set[str]:
    out = run([os.environ["REF_PY"], DRIVER, "classes", apk, "8"], cwd=os.environ["REF_ROOT"], env=asc_environment())
    return {to_java_name(line) for line in out.splitlines() if line.strip()}


ROW_PREFIX = " | matched=("


def split_rows(lines: list[str]) -> tuple[dict[str, Counter[str]], int]:
    """Map each row's identity to a multiset (Counter) of matched texts.

    A row reads `<dex> | <class>-><method> | matched=(<text>)`. Occurrences are
    kept per (identity, matched text) instead of a plain dict keyed by identity,
    so one identity reported twice - a same-name overload hit at two sites, or
    once by each side with a different matched text - is compared occurrence by
    occurrence (audit QUAL-01; the dict collapse this replaces was part of
    audit V04's representation gap). Limitation: neither side prints the
    prototype - the reference formats `Lclass;->name` at asc_handler.py:69-78,
    rasc at src/dex/mod.rs `target_name` (matched joined with "; ") - so two
    overloads of one method still share the identity string unless their
    matched texts differ. The complete identity (prototype, numeric indexes,
    duplicate counts) is the A01/A03 contract, not this script's.

    The reference implementation prints the matched text verbatim, so a string
    constant that spans lines arrives as extra fragment lines and the text
    itself is cut short; those lines have no identity and are counted
    separately.
    """
    identities: dict[str, Counter[str]] = {}
    fragments = 0
    for line in lines:
        head, marker, text = line.partition(ROW_PREFIX)
        if not marker or " | " not in head or "->" not in head:
            fragments += 1
            continue
        text = text[:-1] if text.endswith(")") else text
        identities.setdefault(head, Counter())[text] += 1
    return identities, fragments


def reference_truncation(theirs: str, ours: str) -> bool:
    """True when `theirs` looks like the reference's cut-short copy of `ours`."""
    if not theirs or len(theirs) >= len(ours):
        return False
    for length in range(1, len(theirs) + 1):
        if theirs[:length] not in ours:
            return False
    return True


def compare_row_multisets(
    ours: dict[str, Counter[str]], theirs: dict[str, Counter[str]], *, allow_truncation: bool = False
) -> dict[str, list]:
    """Pair the occurrences of each row identity between the two sides.

    Exact (identity, text) occurrences pair first; leftovers then try the
    reference's cut-short-text tolerance when `allow_truncation` is set.
    Returns rasc-only / asc-only occurrence lists, the identities whose
    leftovers could not be paired at all (a matched-text difference), and the
    occurrences only paired via the truncation tolerance.
    """
    rasc_only: list[tuple[str, str]] = []
    asc_only: list[tuple[str, str]] = []
    text_mismatch: list[tuple[str, str, str]] = []
    truncated: list[tuple[str, str, str]] = []
    for head in set(ours) | set(theirs):
        o_texts = ours.get(head, Counter())
        t_texts = theirs.get(head, Counter())
        if o_texts == t_texts:
            continue
        common = o_texts & t_texts
        o_left = list((o_texts - common).elements())
        t_left = list((t_texts - common).elements())
        if allow_truncation and o_left and t_left:
            taken = [False] * len(t_left)
            unmatched = []
            for o_text in o_left:
                for index, t_text in enumerate(t_left):
                    if not taken[index] and reference_truncation(t_text, o_text):
                        taken[index] = True
                        truncated.append((head, o_text, t_text))
                        break
                else:
                    unmatched.append(o_text)
            o_left = unmatched
            t_left = [text for index, text in enumerate(t_left) if not taken[index]]
        rasc_only.extend((head, text) for text in o_left)
        asc_only.extend((head, text) for text in t_left)
        if o_left and t_left:
            text_mismatch.append((head, o_left[0], t_left[0]))
    return {"rasc_only": rasc_only, "asc_only": asc_only, "text_mismatch": text_mismatch, "truncated": truncated}


class Exemptions:
    """Row-precise parity exemptions loaded from bench/parity_allowlist.json.

    An entry exempts every occurrence of one row identity under one query for
    one APK sha256; there is no way to exempt a whole query, APK or side, and
    manifest differences cannot be exempted at all. Every loaded entry must be
    hit at least once by the run: `unused()` lists the stale ones and the
    caller treats them as failures, so an expired exemption breaks the gate
    instead of silently narrowing it.
    """

    def __init__(self, entries: list[dict]):
        self._entries = {(e["apk_sha256"], e["query"], e["row_identity"]): e for e in entries}
        self._hit: set[tuple[str, str, str]] = set()

    def take(self, apk_sha256: str, query: str, row_identity: str) -> bool:
        key = (apk_sha256, query, row_identity)
        if key in self._entries:
            self._hit.add(key)
            return True
        return False

    def unused(self) -> list[dict]:
        return [entry for key, entry in self._entries.items() if key not in self._hit]


def load_allowlist(path: str | None = None) -> list[dict]:
    """Read and validate the allowlist; a malformed entry stops the run."""
    if path is None:
        path = ALLOWLIST_PATH
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return []
    entries = data.get("entries", [])
    required = {"apk_sha256", "query", "row_identity", "reason", "evidence"}
    for entry in entries:
        missing = required - set(entry)
        if missing:
            raise SystemExit(f"{path}: allowlist entry {entry!r} lacks {sorted(missing)}")
    return entries


def check_rows(
    label: str,
    query: str,
    ours_lines: list[str],
    theirs_lines: list[str],
    *,
    exemptions: Exemptions | None = None,
    apk_sha256: str = "",
    allow_truncation: bool = False,
) -> dict:
    """Compare two row-line lists and return failures, report lines and counts.

    The APK runner calls this with real subprocess output and `--self-test`
    calls it with built-in samples, so the gate and its self-test exercise the
    same comparison code.
    """
    if exemptions is None:
        exemptions = Exemptions([])
    ours, _ = split_rows(ours_lines)
    theirs, fragments = split_rows(theirs_lines)
    diff = compare_row_multisets(ours, theirs, allow_truncation=allow_truncation)
    ours_count = sum(sum(texts.values()) for texts in ours.values())
    theirs_count = sum(sum(texts.values()) for texts in theirs.values())

    exempted = 0
    rasc_only: list[tuple[str, str]] = []
    asc_only: list[tuple[str, str]] = []
    text_bad: list[tuple[str, str, str]] = []
    for head, text in diff["rasc_only"]:
        if exemptions.take(apk_sha256, query, head):
            exempted += 1
        else:
            rasc_only.append((head, text))
    for head, text in diff["asc_only"]:
        if exemptions.take(apk_sha256, query, head):
            exempted += 1
        else:
            asc_only.append((head, text))
    for head, o_text, t_text in diff["text_mismatch"]:
        if exemptions.take(apk_sha256, query, head):
            exempted += 1
        else:
            text_bad.append((head, o_text, t_text))

    report: list[str] = []
    failures = 0
    if rasc_only or asc_only or text_bad:
        failures = 1
        report.append(f"  {label} {query}: DIFFER rasc={ours_count} asc={theirs_count} row occurrences")
        for head, text in rasc_only[:2]:
            report.append(f"    only rasc: {head} | matched=({text})")
        for head, text in asc_only[:2]:
            report.append(f"    only asc : {head} | matched=({text})")
        for head, o_text, t_text in text_bad[:2]:
            report.append(f"    text differs in {head}: rasc {o_text!r} vs asc {t_text!r}")
        if exempted:
            report.append(f"    ({exempted} occurrence(s) exempted via {os.path.basename(ALLOWLIST_PATH)})")
    else:
        note = f"  {label} {query}: {ours_count} row occurrences identical"
        if diff["truncated"]:
            note += f", matched text cut short in {len(diff['truncated'])} (reference truncation)"
        if fragments:
            note += f", {fragments} reference fragment line(s)"
        if exempted:
            note += f", {exempted} exempted occurrence(s)"
        report.append(note)
    return {"failures": failures, "report": report, "ours_rows": ours_count}


# Broad sweep across all four modes. Against the fixed reference SHA ccc6bae
# the reference DOES verify instruction boundaries before emitting a row:
# byte-scan candidates are looked up in a 16-byte dense bucket table keyed by
# `insn_off >> 4` and re-verified with INSN_VERIFY.fullmatch over the bytes
# from the owning method's first instruction up to the candidate offset
# (src/asc_core/findrefs/locator/insn_locator.py:180-200; the per-opcode-length
# chain regex is built at :46-57). The old comment here claimed the reference
# had no boundary check, which does not match that source. Reference-only rows
# therefore have other, here-unclassified causes - e.g. a bucket holding
# several methods is verified against midx[0] only and credited to every method
# of the list (insn_locator.py:196-198), the chain regex can walk switch/array
# payload bytes (a payload's leading unit is byte 0x00 = `nop`,
# src/asc_core/models/dvm_opcode.py:73), or regex-vs-literal query semantics
# (string_locator.py:55 compiles the query as a regex) - and each one must be
# arbitrated with bench/row_oracle.py before it may be exempted here. The
# check itself is bidirectional: a row either side reports and the other misses
# is a failure unless precisely exempted in bench/parity_allowlist.json.
SWEEP_QUERIES = [
    "string http",
    "string android.permission",
    "string Lcom",
    "string key",
    "string value",
    "string UTF-8",
    "string config",
    "type Ljava/lang/String;",
    "type Activity",
    "type android",
    "method <init>",
    "method on",
    "method get",
    "field m",
    "field INSTANCE",
]


# Patterns the reference treats literally enough to compare filtered results.
# The reference compiles the query as a regex and searches it over the MUTF-8
# string-data region (string_locator.py:47-63, `re.compile` at :55), and the
# fuzzy class filter reaches the same locator through TypeLocator
# (type_locator.py:34-46), so `.` is a wildcard and `$` an anchor there (audit
# G01/D01). Letters, digits, underscores, slashes and dots in a package prefix
# are safe - the dot wildcard still matches the `/` of the real descriptor.
SAFE_PATTERN = re.compile(r"^[A-Za-z0-9_./]+$")


def rasc_rows(binary: str, apk: str, query: str) -> list[str]:
    args = query.split()
    return run([binary, "findrefs", "--threads", "8", apk, *args]).splitlines()


def asc_rows(apk: str, query: str) -> list[str]:
    args = query.split()
    out = run(
        [os.environ["REF_PY"], os.path.join(os.environ["REF_ROOT"], "main.py"), "findrefs", "--threads", "8", apk, *args],
        cwd=os.environ["REF_ROOT"],
        env=asc_environment(),
    )
    return out.splitlines()


def normalize_xml_text(text: str | None) -> str:
    """Normalize renderer whitespace out of a text or tail node.

    The two manifest renderers pretty-print differently (rasc emits an XML
    declaration plus four-space indentation; the reference emits neither), and
    that indentation lands in element.text/tail. Rule, applied per line:
    whitespace-only text normalizes to "", otherwise each line is stripped of
    its leading and trailing whitespace and whitespace-only lines are dropped.
    Every internal non-whitespace character sequence survives, so a
    non-whitespace content difference can never be normalized away.
    """
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def attribute_value(text: str | None) -> str | None:
    """Hex values differ between the two renderers in case and zero padding;
    compare them numerically."""
    if text is not None and text.startswith("0x"):
        try:
            return str(int(text, 16))
        except ValueError:
            return text
    return text


def tree_shape(text: str):
    """(tag, sorted attributes, normalized text, normalized tail, children)."""

    def node(element):
        attributes = tuple(sorted((name, attribute_value(value)) for name, value in element.attrib.items()))
        return (
            element.tag,
            attributes,
            normalize_xml_text(element.text),
            normalize_xml_text(element.tail),
            tuple(node(child) for child in element),
        )

    return node(ElementTree.fromstring(text))


def manifest_differences(ours: str, theirs: str, limit: int = 8) -> list[str]:
    """First few structural differences, as `path: what differs` lines."""
    ours_tree = ElementTree.fromstring(ours)
    theirs_tree = ElementTree.fromstring(theirs)
    out: list[str] = []

    def walk(x, y, path):
        if len(out) >= limit:
            return
        if x.tag != y.tag:
            out.append(f"{path}: tag {x.tag!r} vs {y.tag!r}")
            return
        if normalize_xml_text(x.text) != normalize_xml_text(y.text):
            out.append(f"{path}/{x.tag}: text {x.text!r} vs {y.text!r}")
        if normalize_xml_text(x.tail) != normalize_xml_text(y.tail):
            out.append(f"{path}/{x.tag}: tail {x.tail!r} vs {y.tail!r}")
        ours_attrs, theirs_attrs = dict(x.attrib), dict(y.attrib)
        for name in sorted(set(ours_attrs) | set(theirs_attrs)):
            ours_value, theirs_value = ours_attrs.get(name), theirs_attrs.get(name)
            if attribute_value(ours_value) != attribute_value(theirs_value):
                out.append(f"{path}/{x.tag}: {name}={ours_value!r} vs {theirs_value!r}")
        if len(x) != len(y):
            out.append(f"{path}/{x.tag}: {len(x)} children vs {len(y)}")
            return
        for index, (child_x, child_y) in enumerate(zip(x, y)):
            walk(child_x, child_y, f"{path}/{x.tag}[{index}]")

    walk(ours_tree, theirs_tree, "root")
    return out


def manifest_failures(ours: str, theirs: str) -> list[str]:
    """[] when the two manifests are equal modulo renderer whitespace.

    Text, tail and attribute differences count as failures (audit QUAL-01:
    the old comparator ignored text/tail entirely and did not fail on manifest
    differences at all).
    """
    return [] if tree_shape(ours) == tree_shape(theirs) else manifest_differences(ours, theirs)


def run_parity(apks: list[str]) -> int:
    binary = os.environ.get("RASC_BIN", os.path.join(ROOT, "target/release/rasc"))
    exemptions = Exemptions(load_allowlist())
    failures = 0
    for apk in apks:
        print(f"=== {os.path.basename(apk)} ===")
        apk_sha256 = sha256_file(apk)

        ours, theirs = rasc_classes(binary, apk), asc_classes(apk)
        if ours == theirs:
            print(f"  classes: {len(ours)} identical")
        else:
            failures += 1
            print(f"  classes: DIFFER rasc={len(ours)} asc={len(theirs)}")
            print(f"    only rasc: {sorted(ours - theirs)[:4]}")
            print(f"    only asc : {sorted(theirs - ours)[:4]}")

        for query in QUERIES:
            result = check_rows(
                "findrefs",
                query,
                rasc_rows(binary, apk, query),
                asc_rows(apk, query),
                exemptions=exemptions,
                apk_sha256=apk_sha256,
                allow_truncation=True,
            )
            failures += result["failures"]
            print("\n".join(result["report"]))

        for query in SWEEP_QUERIES:
            result = check_rows(
                "sweep",
                query,
                rasc_rows(binary, apk, query),
                asc_rows(apk, query),
                exemptions=exemptions,
                apk_sha256=apk_sha256,
                allow_truncation=True,
            )
            failures += result["failures"]
            print("\n".join(result["report"]))

        # Filter sweep: the class filters are their own code path (exact, fuzzy
        # and the dotted-name normalization), and the reference matches them
        # with `re` (see SAFE_PATTERN), so only literal-safe package prefixes
        # are compared. Bidirectional like the query sweep: any row occurrence
        # one side reports and the other misses is a failure (or an exempted
        # row). The class pattern constrains the class the reference points at,
        # so the patterns are derived from the unfiltered rows themselves - a
        # package that really does define the queried member. Otherwise every
        # combination would trivially return nothing on both sides and check no
        # rows at all.
        checked_rows = 0
        filtered = 0
        for member in ("onCreate", "on"):
            base_rows, _ = split_rows(rasc_rows(binary, apk, f"method {member}"))
            counts: dict[str, int] = {}
            for row in base_rows:
                parts = row.split(" | ")
                if len(parts) != 2 or "->" not in parts[1]:
                    continue
                name = to_java_name(parts[1].split("->", 1)[0])
                if "$" in name or "." not in name:
                    continue
                prefix = name.rsplit(".", 1)[0]
                if SAFE_PATTERN.match(prefix):
                    counts[prefix] = counts.get(prefix, 0) + 1
            for pattern in [p for p, _ in sorted(counts.items(), key=lambda kv: -kv[1])[:4]]:
                for extra in ([], ["--fuzzy-class"]):
                    args = f"method {member} --class {pattern}"
                    if extra:
                        args += " --fuzzy-class"
                    result = check_rows(
                        "filter",
                        args,
                        rasc_rows(binary, apk, args),
                        asc_rows(apk, args),
                        exemptions=exemptions,
                        apk_sha256=apk_sha256,
                        allow_truncation=True,
                    )
                    failures += result["failures"]
                    filtered += 1
                    checked_rows += result["ours_rows"]
        print(f"  filters: {filtered} combination(s), {checked_rows} rows checked")

        ours_manifest = run([binary, "manifest", apk])
        theirs_manifest = run(
            [os.environ["REF_PY"], DRIVER, "manifest", apk], cwd=os.environ["REF_ROOT"], env=asc_environment()
        )
        differences = manifest_failures(ours_manifest, theirs_manifest)
        if not differences:
            print(
                f"  manifest: content identical, formatting differs "
                f"(rasc {len(ours_manifest.splitlines())} lines vs asc {len(theirs_manifest.splitlines())} lines)"
            )
        else:
            failures += 1
            print(f"  manifest: content differs in {len(differences)} place(s)")
            for line in differences[:4]:
                print(f"    {line}")

    for entry in exemptions.unused():
        failures += 1
        print(
            "unused exemption (never hit by this run; remove or fix it): "
            f"{entry['apk_sha256'][:12]}... {entry['query']!r} {entry['row_identity']!r}"
        )
    print("parity check:", "ok" if failures == 0 else f"{failures} failure(s)")
    return 1 if failures else 0


# --- self-test ----------------------------------------------------------------
#
# Built-in samples for `--self-test`: the comparator must pass an untampered
# control pair and fail three tamperings - (a) a reference row deleted from
# theirs, (b) a manifest text node changed in ours, (c) a manifest attribute
# value changed in ours. Anything else (a tamper that still passes, a control
# that fails, a stale exemption that goes unnoticed) exits non-zero.

SELF_TEST_ROWS = [
    "classes.dex | Lcom/example/A;->run | matched=(Lcom/example/A;->token)",
    "classes.dex | Lcom/example/A;->run | matched=(Lcom/example/B;->token)",
    "classes.dex | Lcom/example/B;->onCreate | matched=('Authorization header')",
    "classes.dex | Lcom/example/C;-><init> | matched=(Lcom/example/C;->flag)",
]

SELF_TEST_MANIFEST_OURS = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:label="Example"
        android:theme="0x7f0a0001">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
            launcher tail
        </activity>
        <meta-data android:name="note">inner note text</meta-data>
    </application>
</manifest>
"""

# Same content, but rendered without a declaration, without indentation, with
# whitespace around the text node, and with the hex attribute in a different
# case/padding: the control pair must compare equal.
SELF_TEST_MANIFEST_THEIRS = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">'
    '<uses-permission android:name="android.permission.INTERNET"/>'
    '<application android:label="Example" android:theme="0x007F0A0001">'
    '<activity android:name=".MainActivity">'
    '<intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>'
    "launcher tail"
    "</activity>"
    '<meta-data android:name="note">\n\tinner note text\n</meta-data>'
    "</application>"
    "</manifest>"
)


def self_test() -> int:
    """Run the comparator over built-in samples; needs no external tool."""
    print("self-test: row multiset comparator")
    failures = 0

    def expect(condition: bool, description: str) -> None:
        nonlocal failures
        print(f"  {'PASS' if condition else 'FAIL'}: {description}")
        if not condition:
            failures += 1

    # Control: identical row lists compare equal.
    result = check_rows("self", "string token", SELF_TEST_ROWS, SELF_TEST_ROWS)
    expect(result["failures"] == 0, f"identical row sets pass ({result['ours_rows']} occurrences)")

    # Tamper (a): delete a real reference row from theirs; the rasc-only row
    # must be a failure.
    tampered = SELF_TEST_ROWS[:1] + SELF_TEST_ROWS[2:]
    result = check_rows("self", "string token", SELF_TEST_ROWS, tampered)
    expect(result["failures"] != 0 and any("only rasc" in line for line in result["report"]),
           "deleting a reference row is a failure")

    # A reference-only row (present in theirs, missing in ours) must fail too:
    # the old sweep only counted these.
    result = check_rows("self", "string token", SELF_TEST_ROWS[:3], SELF_TEST_ROWS)
    expect(result["failures"] != 0 and any("only asc" in line for line in result["report"]),
           "a reference-only row is a failure (bidirectional)")

    # Duplicate occurrences of one identity (the same-name overload case) are
    # compared per count; the old dict identity collapsed them to a single row.
    doubled = SELF_TEST_ROWS + [SELF_TEST_ROWS[1]]
    result = check_rows("self", "string token", doubled, SELF_TEST_ROWS)
    expect(result["failures"] != 0, "a duplicated rasc row occurrence is a failure")
    result = check_rows("self", "string token", SELF_TEST_ROWS, doubled)
    expect(result["failures"] != 0, "a duplicated reference row occurrence is a failure")

    # Matched-text differences on a shared identity fail; the reference's
    # cut-short copy of a longer string is tolerated via reference_truncation.
    swapped = list(SELF_TEST_ROWS)
    swapped[2] = "classes.dex | Lcom/example/B;->onCreate | matched=('Authorization')"
    result = check_rows("self", "string token", SELF_TEST_ROWS, swapped)
    expect(result["failures"] != 0 and any("text differs" in line for line in result["report"]),
           "a changed matched text is a failure")
    cut = list(SELF_TEST_ROWS)
    cut[2] = "classes.dex | Lcom/example/B;->onCreate | matched=('Authorization h)"
    result = check_rows("self", "string token", SELF_TEST_ROWS, cut, allow_truncation=True)
    expect(result["failures"] == 0 and any("cut short" in line for line in result["report"]),
           "the reference's cut-short matched text is tolerated")

    # Exemptions: one precise entry suppresses its row, an entry the run never
    # hits stays unused and must surface as a failure of the gate.
    head = SELF_TEST_ROWS[3].partition(ROW_PREFIX)[0]
    hit_entry = {"apk_sha256": "a" * 64, "query": "string token", "row_identity": head,
                 "reason": "self-test", "evidence": "self-test"}
    stray_entry = {"apk_sha256": "b" * 64, "query": "string token", "row_identity": head,
                   "reason": "self-test", "evidence": "self-test"}
    exemptions = Exemptions([hit_entry, stray_entry])
    result = check_rows("self", "string token", SELF_TEST_ROWS[:3], SELF_TEST_ROWS,
                        exemptions=exemptions, apk_sha256="a" * 64)
    expect(result["failures"] == 0, "an exempted reference-only row passes")
    expect(len(exemptions.unused()) == 1, "an exemption the run never hits is reported as stale")

    print("self-test: manifest comparator")
    expect(normalize_xml_text("   \n\t  ") == "", "whitespace-only text normalizes to empty")
    expect(normalize_xml_text("  a  b  ") == "a  b", "internal spacing of a text node survives")
    expect(normalize_xml_text("  x\n    y  ") == "x\ny", "per-line indentation is stripped")
    # Control: the untampered pair compares equal modulo renderer whitespace.
    expect(not manifest_failures(SELF_TEST_MANIFEST_OURS, SELF_TEST_MANIFEST_THEIRS),
           "untampered manifest pair is ok (declaration, indentation, hex case/padding differ)")
    # Tamper (b): change a text node in ours.
    text_tampered = SELF_TEST_MANIFEST_OURS.replace(">inner note text<", ">tampered note text<")
    expect(text_tampered != SELF_TEST_MANIFEST_OURS and
           any("text" in line for line in manifest_failures(text_tampered, SELF_TEST_MANIFEST_THEIRS)),
           "changing ours manifest text node is a failure")
    # Tamper (c): change an attribute value in ours. ElementTree reports
    # namespace-prefixed attributes in Clark notation (`{uri}label`), so match
    # the local name.
    attr_tampered = SELF_TEST_MANIFEST_OURS.replace('android:label="Example"', 'android:label="Example2"')
    expect(attr_tampered != SELF_TEST_MANIFEST_OURS and
           any("label" in line for line in manifest_failures(attr_tampered, SELF_TEST_MANIFEST_THEIRS)),
           "changing ours manifest attribute value is a failure")
    # A non-whitespace tail difference is a failure too (text/tail were
    # previously not compared at all).
    tail_tampered = SELF_TEST_MANIFEST_OURS.replace("launcher tail", "launcher taip")
    expect(any("tail" in line for line in manifest_failures(tail_tampered, SELF_TEST_MANIFEST_THEIRS)),
           "changing ours manifest tail is a failure")

    print("self-test:", "ok" if failures == 0 else f"{failures} failure(s)")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    apks = [arg for arg in argv if arg != "--self-test"]
    if not apks:
        raise SystemExit(__doc__)
    return run_parity(apks)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
