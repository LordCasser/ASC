#!/usr/bin/env python3
"""Arbitrate the rows the reference reports and rasc does not.

How the two sides find references (reference fixed at SHA ccc6bae):
  * rasc decodes instructions by opcode width and counts real instructions.
  * the reference byte-scans the code region for opcode + referenced-index
    patterns (src/asc_core/findrefs/scan/code_item_scan.py), maps each
    candidate offset through a 16-byte dense bucket table keyed by
    `insn_off >> 4`, and re-verifies instruction boundaries with
    INSN_VERIFY.fullmatch over the bytes from the owning method's first
    instruction up to the candidate offset
    (src/asc_core/findrefs/locator/insn_locator.py:169-204; the per-opcode-
    length chain regex is built at :46-57).

The reference therefore DOES verify instruction boundaries at this SHA. The
old header of this file claimed it located references "without an
instruction-boundary check", which does not match that source. The check is
still weaker than a real decoder:
  * a bucket that ends up holding several methods is verified against
    midx[0]'s start only, and the hit is credited to every method of the list
    (insn_locator.py:196-198) - a hit inside one method can be reported for a
    neighbour sharing its 16-byte bucket;
  * the chain regex accepts any concatenation of valid opcode/length units,
    so it can walk into packed-switch / fill-array payload data (a payload's
    leading unit is byte 0x00 = `nop`, oplen 1, src/asc_core/models/
    dvm_opcode.py:73) and can accept alternative opcode-length parses of the
    same bytes.

Reference-only rows are consequently not pre-explained by any single cause.
This script checks them row by row with an independent decoder: Androguard
parses the code item and yields real instructions, and a row is a *real*
reference only if the named method contains an instruction of the right kind
whose operand mentions the query. Any row the oracle calls real is a candidate
rasc miss and is printed for inspection.

    RASC_BIN=target/release/rasc REF_ROOT=... REF_PY=... \
      python3 bench/row_oracle.py app.apk <string|type|field|method> <query> [max rows]
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import zipfile

logging.disable(logging.CRITICAL)

# The operand that the query is compared against, per kind: the string literal, the
# type descriptor, `Lclass;->field`, or `Lclass;->method(params)ret`.
#
# Verified reference semantics at ccc6bae: a member query selects members by NAME
# substring - the query is compiled as a regex and searched over the MUTF-8
# string-data region (string_locator.py:47-63, `re.compile` at :55), then mapped
# to member ids through the name string index (method_locator.py:104-114 without
# a class filter and :72-78 with a precise one; field_locator.py:105-115 and
# :73-79 are the field twins). It never matches the whole `Lclass;->member`
# text: that text is display formatting assembled when the row is printed
# (asc_handler.py:69-78, without the prototype - audit V04). Comparing the
# member part of the operand against the query therefore mirrors the reference's
# own selection; comparing the whole instruction output instead would let a
# short query match the class name.
OPERAND = {
    "string": re.compile(r"'([^']*)'"),
    "type": re.compile(r"(L[^;]*;)"),
    "field": re.compile(r"(L[^;]*;->[^ ]+)"),
    "method": re.compile(r"(L[^;]*;->[^()]*\([^)]*\)[^ ]*)"),
}

PREFIXES = {
    "string": ("const-string",),
    "type": (
        "const-class",
        "check-cast",
        "instance-of",
        "new-instance",
        "new-array",
        "filled-new-array",
    ),
    "field": ("iget", "iput", "sget", "sput"),
    "method": ("invoke",),
}


def rows(command: list[str], cwd: str | None = None) -> set[str]:
    out = subprocess.run(command, capture_output=True, text=True, cwd=cwd)
    if out.returncode != 0:
        raise SystemExit(f"command failed ({out.returncode}): {' '.join(command)}\n{out.stderr[:300]}")
    return set(out.stdout.splitlines())


def identity(row: str) -> tuple[str, str, str, str] | None:
    """(dex entry, class descriptor, method name, matched text) of a row, or None.

    A row reads `<dex> | <class>-><method> | matched=(<text>)`; the reference
    also emits fragments of multi-line matched text, which carry no identity.
    The matched text is part of the identity so same-name overloads referencing
    different members are not merged into one row. Limitation: neither side
    prints the containing method's prototype (audit V04), so overloads that
    also share every matched text still merge; such rows are counted as
    ambiguous in the report below.
    """
    head, marker, text = row.partition(" | matched=(")
    if not marker or " | " not in head:
        return None
    dex_name, _, target = head.partition(" | ")
    if "->" not in target:
        return None
    class_name, _, method_name = target.partition("->")
    matched = text[:-1] if text.endswith(")") else text
    return dex_name, class_name.strip(), method_name.strip(), matched


def main() -> int:
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    apk = sys.argv[1]
    # Accept both "<kind> <query>" as one argument and as two.
    kind, _, query = sys.argv[2].partition(" ")
    if not query:
        kind, query = sys.argv[2], sys.argv[3]
        rest = sys.argv[4:]
    else:
        rest = sys.argv[3:]
    if kind not in PREFIXES:
        raise SystemExit(f"unknown query kind {kind!r}; expected one of {sorted(PREFIXES)}")
    limit = int(rest[0]) if rest else 200
    prefixes = PREFIXES[kind]

    binary = os.environ.get("RASC_BIN", "target/release/rasc")
    ours = rows([binary, "findrefs", "--threads", "8", apk, kind, query])
    theirs = rows(
        [
            os.environ["REF_PY"],
            os.path.join(os.environ["REF_ROOT"], "main.py"),
            "findrefs",
            "--threads",
            "8",
            apk,
            kind,
            query,
        ],
        cwd=os.environ["REF_ROOT"],
    )
    ours_ids = {row for row in (identity(r) for r in ours) if row}
    asc_only = [i for i in (identity(r) for r in theirs) if i and i not in ours_ids][:limit]
    print(f"{os.path.basename(apk)} {kind} {query!r}: rasc {len(ours_ids)} rows, asc-only {len(asc_only)} checked")

    from androguard.core.dex import DEX  # imported late: it is slow and noisy
    try:  # androguard logs through loguru, which logging.disable cannot touch
        from loguru import logger

        logger.remove()
    except Exception:  # noqa: BLE001 - silencing logs is best effort
        pass

    dexes: dict[str, DEX] = {}
    dex_errors: dict[str, str] = {}

    def load_dex(dex_name: str) -> DEX:
        if dex_name in dex_errors:
            raise RuntimeError(dex_errors[dex_name])
        if dex_name not in dexes:
            try:
                with zipfile.ZipFile(apk) as archive:
                    dexes[dex_name] = DEX(archive.read(dex_name))
            except Exception as exc:  # noqa: BLE001 - report and skip this row
                dex_errors[dex_name] = f"{type(exc).__name__}: {str(exc)[:160]}"
                raise
        return dexes[dex_name]

    # Categories for an asc-only row, arbitrated against the ccc6bae sources:
    #   name  - a real instruction of the right family in this method
    #           references a member whose *name* contains the query. The
    #           reference selects member ids by name (see the OPERAND comment:
    #           string_locator.py:47-63 regex over the string-data region,
    #           mapped through method_locator.py:104-114/:72-78 or
    #           field_locator.py:105-115/:73-79), so this is what the
    #           reference intended to match; a row here that rasc misses is a
    #           candidate rasc miss.
    #   class - a real instruction references a member whose class part
    #           contains the query but whose name does not. The reference
    #           never matches `Lclass;->member` as one string, so the row
    #           means the byte-level candidate index at the scanned offset was
    #           in the target set while the real operand names another member:
    #           an alignment/boundary coincidence, not a rasc miss.
    #   none  - no real instruction of the family in this method mentions the
    #           query at all: the byte scan matched opcode+index bytes that
    #           are not a real reference - operand or payload bytes forming
    #           the pattern (the chain regex can walk payloads, see the module
    #           docstring) - or a bucket-list hit credited to this method
    #           (insn_locator.py:196-198).
    real, class_only = [], []
    fake = missing = ambiguous = decode_errors = 0
    for dex_name, class_name, method_name, matched_text in asc_only:
        try:
            dex = load_dex(dex_name)
            overloads = []
            for cls in dex.get_classes():
                if cls.get_name() == class_name:
                    overloads = [m for m in cls.get_methods() if m.get_name() == method_name]
                    break
        except Exception as exc:  # noqa: BLE001 - report and skip this row
            decode_errors += 1
            print(
                f"  decode failed for row {dex_name} {class_name}->{method_name} "
                f"(matched={matched_text!r}): {exc}"
            )
            continue
        if not overloads:
            missing += 1
            print(f"  row method not found by decoder: {dex_name} {class_name}->{method_name}")
            continue
        if len(overloads) > 1:
            # The row identity carries no prototype (audit V04), so the
            # reference cannot say which overload it means either; scan them
            # all and count the row as ambiguous.
            ambiguous += 1
        name_hit = class_hit = None
        for method in overloads:
            for instruction in method.get_instructions():
                if not instruction.get_name().startswith(prefixes):
                    continue
                output = instruction.get_output()
                for operand in OPERAND[kind].findall(output):
                    if query not in operand:
                        continue
                    member = operand.rsplit("->", 1)[-1]
                    if query in member:
                        name_hit = f"{instruction.get_name()} {output}"
                        break
                    class_hit = f"{instruction.get_name()} {output}"
                if name_hit:
                    break
            if name_hit:
                break
        if name_hit:
            real.append((class_name, method_name, matched_text, name_hit))
        elif class_hit:
            class_only.append((class_name, method_name, matched_text, class_hit))
        else:
            fake += 1

    print(f"  member-name hits (would be rasc misses): {len(real)}")
    for class_name, method_name, matched_text, hit in real[:5]:
        print(f"    {class_name}->{method_name} matched=({matched_text}): {hit[:120]}")
    print(f"  class-part-only hits (candidate-idx coincidence, not a rasc miss): {len(class_only)}")
    for class_name, method_name, matched_text, hit in class_only[:5]:
        print(f"    {class_name}->{method_name} matched=({matched_text}): {hit[:120]}")
    print(f"  no real instruction references it (byte-scan false positive: payload/operand bytes or bucket-list attribution): {fake}")
    if ambiguous:
        print(f"  rows whose containing method has same-name overloads: {ambiguous} (identity ambiguous - neither side prints a prototype, audit V04)")
    if missing:
        print(f"  rows whose method the decoder could not locate: {missing}")
    if decode_errors:
        print(f"  rows skipped because the DEX could not be decoded: {decode_errors}")
    return 1 if real else 0


if __name__ == "__main__":
    sys.exit(main())
