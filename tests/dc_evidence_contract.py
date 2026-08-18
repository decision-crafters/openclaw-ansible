#!/usr/bin/env python3
"""Contract tests for how role tasks READ EVIDENCE from append-only sources.

    python3 tests/dc_evidence_contract.py

WHY THIS FILE EXISTS

Three times in one workstream, a check asked a PRESENT-TENSE question of an
APPEND-ONLY source and reported history as current state:

  1. 2026-08-17  A checker grepped the last 12 log lines for "channel users
     resolved". The window still held the PRE-mutation block, so it matched
     history, declared the deny state ineffective, and aborted a test that had
     in fact worked.

  2. 2026-08-18  A forensic script searched a truncated 7-line log and reported
     "this gateway never saw the event" -- absence of DATA scored as evidence of
     ABSENCE, inside a check written to prevent exactly that.

  3. 2026-08-18  sender_denial_apply.yml counted resolutions across the whole
     log and reported the founder AND the placeholder both permitted. That is
     IMPOSSIBLE in a single provider start, and the impossibility was visible in
     the output -- but nothing checked for it.

The common defect is not carelessness; it is that a log spanning N state changes
answers "what has ever been true", and every one of these checks needed "what is
true now". Those differ by an anchor.

THE THREE RULES

  ANCHOR        A present-tense query must be scoped to the marker that
                separates before from after -- here, the last `starting
                provider` line. Querying raw `.stdout` is a violation.

  FLOOR         A check must refuse to score a source too small to be evidence,
                returning INSUFFICIENT EVIDENCE rather than a confident absence.
                This is NO OUTPUT != REFUSAL applied to evidence gathering.

  IMPOSSIBILITY Mutually exclusive outcomes must not both be reportable as true.
                A check that can emit an impossible state has not verified
                itself, and instance 3 shipped exactly that.

These are enforced mechanically because a prose rule is advisory. The whole
governance model in this repository rests on that distinction.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROLE = Path(__file__).resolve().parent.parent / "roles" / "dc-governed-config"
TASKS = sorted((ROLE / "tasks").glob("*.yml"))

# A task file may opt out only by saying so, in writing, at the top.
WAIVER = "EVIDENCE-ANCHOR-WAIVED"
ANCHOR_MARKER = "starting provider"


def _tasks(path: Path) -> list[dict]:
    try:
        loaded = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return []
    return loaded if isinstance(loaded, list) else []


def _log_registers(tasks: list[dict]) -> set[str]:
    """Registers holding output of a `logs` invocation — the append-only source."""
    found = set()
    for t in tasks:
        cmd = t.get("ansible.builtin.command") or t.get("command") or {}
        argv = str(cmd.get("argv", "")) if isinstance(cmd, dict) else str(cmd)
        if "'logs'" in argv and t.get("register"):
            found.add(t["register"])
    return found


def main() -> int:
    checks: list[tuple[str, bool]] = []
    violations: list[str] = []
    cumulative: dict[str, set[str]] = {}
    present: dict[str, set[str]] = {}
    floors_missing: list[str] = []
    anchored_files: list[str] = []

    for path in TASKS:
        tasks = _tasks(path)
        if not tasks:
            continue
        text = path.read_text()
        registers = _log_registers(tasks)
        if not registers:
            continue
        if WAIVER in text:
            continue

        # Parse the per-file EVIDENCE-CLASS declarations.
        for kind, store in (("cumulative", cumulative), ("present", present)):
            for m in re.finditer(rf"EVIDENCE-CLASS:\s*{kind}\s*=\s*(.+)", text):
                store.setdefault(path.name, set()).update(
                    n.strip() for n in m.group(1).split(",") if n.strip())

        anchored_files.append(path.name)

        # --- ANCHOR -------------------------------------------------------
        # Any regex/search over the RAW stdout of a log register is a
        # present-tense question asked of the whole history.
        # EVERY string in the task, not just set_fact values.
        #
        # The first version scanned set_fact only. The bug that motivated this
        # contract -- a rollback assertion matching a PRE-restore log line and
        # confirming restoration that had not happened -- lives in an `assert`,
        # and was invisible to that scan. It was caught the first time only
        # incidentally, because the file happened to contain no anchor at all.
        # A contract with a blind spot exactly where the known bug lives is
        # worse than none: it certifies the thing it cannot see.
        def _strings(node, label):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield from _strings(v, f"{label}.{k}" if label else str(k))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    yield from _strings(v, f"{label}[{i}]")
            elif isinstance(node, str):
                yield label, node

        for t in tasks:
            name = str(t.get("name", "?"))
            for var, expr in _strings(
                    {k: v for k, v in t.items() if k not in ("name", "tags")}, ""):
                var = var or name
                e = str(expr)
                for reg in registers:
                    raw = f"{reg}.stdout"
                    if raw not in e:
                        continue
                    # Every way this codebase interrogates log text. `is
                    # search(...)` was missing from the first version, and that
                    # is precisely the form the rollback assertion used -- so
                    # the contract silently passed the one bug it was written
                    # for. Two mutation runs were needed to notice.
                    QUERY_FORMS = ("regex_findall", "regex_search",
                                   "select('search'", 'select("search"',
                                   "is search", "is match",
                                   "| search", "| match")
                    queries = any(k in e for k in QUERY_FORMS)
                    # Deriving the anchor itself is the one legitimate raw read.
                    derives_anchor = "split(" in e and "last" in e
                    if not queries or derives_anchor:
                        continue
                    # A CUMULATIVE question -- "what has ever happened" -- is
                    # legitimately asked of the whole log. A PRESENT question is
                    # not. The author must say which, because the recurring bug
                    # was writing one while believing it was the other.
                    if any(c in var for c in cumulative.get(path.name, set())):
                        continue
                    if any(c in var for c in present.get(path.name, set())):
                        violations.append(
                            f"{path.name}: {var} is declared PRESENT but reads raw {raw}")
                    else:
                        violations.append(
                            f"{path.name}: {var} queries raw {raw} and is UNCLASSIFIED "
                            f"(add it to an EVIDENCE-CLASS line)")

        # --- ANCHOR PRESENT AT ALL ----------------------------------------
        checks.append((
            f"{path.name} derives an anchored window",
            f"split('{ANCHOR_MARKER}')" in text or f'split("{ANCHOR_MARKER}")' in text,
        ))

        # --- FLOOR --------------------------------------------------------
        # Must refuse on a source too small to be evidence.
        has_floor = ("min_lines" in text or "INSUFFICIENT EVIDENCE" in text
                     or "cannot be anchored" in text)
        if not has_floor:
            floors_missing.append(path.name)

    checks.append(("no present-tense query reads a raw, unanchored log", not violations))
    for v in violations:
        print(f"        VIOLATION -> {v}")

    checks.append(("every log-reading file refuses on insufficient source", not floors_missing))
    for f in floors_missing:
        print(f"        NO FLOOR  -> {f}")

    checks.append(("at least one file is under this contract (the test is wired up)",
                   len(anchored_files) > 0))

    # --- IMPOSSIBILITY ----------------------------------------------------
    # sender_denial_apply reports a placeholder count and a founder count. Both
    # non-zero is impossible in one provider start and must be refused, not
    # rendered. This asserts the task says so.
    sda = ROLE / "tasks" / "sender_denial_apply.yml"
    if sda.exists():
        s = sda.read_text()
        checks.append((
            "the sender-denial check refuses when the window cannot be anchored",
            "cannot be anchored" in s and "dc_fail_closed" in s,
        ))
        checks.append((
            "the sender-denial check requires founder ABSENT and placeholder PRESENT",
            "dc_sd_resolved_founder | length) == 0" in s
            and "dc_sd_resolved_placeholder | length) > 0" in s,
        ))

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {n}")
    if failed:
        print(f"\n{len(failed)} evidence-contract check(s) failed.")
        return 1
    print(f"\nAll {len(checks)} evidence-contract checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
