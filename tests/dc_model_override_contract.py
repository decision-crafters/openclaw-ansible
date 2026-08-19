#!/usr/bin/env python3
"""Anti-bypass contract for per-run model overrides. TASK-242.

    python3 tests/dc_model_override_contract.py

`openclaw agent --model <id>` overrides an agent's pinned model at the CALL
SITE. It lives in the CLI, not in openclaw.json, so configuration auditing
cannot see it: `agents.list` can be perfectly pinned while every run passes
something else. Until 2026-08-19 the harnesses avoided it by COMMENT.

This workstream has demonstrated four times over that a written-down rule is not
a control. Founder authorization 2026-08-19 requires the prohibition to be
mechanical: default deny, exceptions only by task-bound grant naming the agent
and the exact model.

WHAT THIS ENFORCES

  1. NO EMITTED --model outside the gate. Comments may discuss it; only the gate
     may put it in an argv. Checked against PARSED YAML, so a comment mentioning
     the flag is correctly ignored while an emission is not.
  2. The gate DEFAULTS TO DENY, before any grant is consulted.
  3. Every agent-invoking harness routes through the gate and composes its
     output, so it has no code path that emits the flag independently.
  4. The schema makes over-broad grants NOT REPRESENTABLE AS VALID, not merely rejected:
     self-acceptance, standing grants and wildcard models are const/pattern
     violations.

Validated by synthetic controls only. No alternate model is ever invoked.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "dc-governed-config"
GATE = ROLE / "tasks" / "model_override_gate.yml"
SCHEMA = ROLE / "files" / "model-override-grant.schema.json"
VALIDATOR = ROLE / "files" / "validate_model_grant.py"

GOOD = {
    "agentId": "dc-research",
    "model": "ollama-cloud/some-other-model:cloud",
    "taskId": "TASK-242",
    "decisionRecord": "https://example.invalid/decision",
    "acceptedBy": "Tosin Akinosho",
    "reason": "A synthetic grant used only to prove the positive control path composes correctly.",
    "reversal": "Delete the grant file; the gate returns to default deny.",
    "singleUse": True,
}


def run_validator(grant: dict, agent: str = "dc-research",
                  task: str = "TASK-242", ledger: str | None = None):
    """Each call gets a FRESH ledger unless one is passed, so negative controls
    do not consume grants for each other. Replay is tested by deliberately
    sharing a ledger across two calls."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(grant, fh)
        path = fh.name
    if ledger is None:
        ledger = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        Path(ledger).unlink()  # absent ledger is the normal first-use case
    p = subprocess.run([sys.executable, str(VALIDATOR), path, str(SCHEMA),
                        agent, task, ledger],
                       capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def emitted_strings(path: Path):
    """Every string in the PARSED task file. Comments are gone by construction,
    which is what separates 'mentions --model' from 'emits --model'."""
    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError:
        return []
    out = []

    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, str):
            out.append(node)
    walk(doc)
    return out


def main() -> int:
    checks: list[tuple[str, bool]] = []
    problems: list[str] = []

    # --- 1. no emitted --model outside the gate ------------------------------
    for path in sorted((ROLE / "tasks").glob("*.yml")):
        if path.name == GATE.name:
            continue
        for s in emitted_strings(path):
            if "--model" in s:
                problems.append(f"{path.name}: emits --model in {s[:70]!r}")
    checks.append(("no task file emits --model outside the gate", not problems))
    for p in problems:
        print(f"        BYPASS -> {p}")

    # --- 2. the gate defaults to deny ----------------------------------------
    gate = yaml.safe_load(GATE.read_text())
    first_fact = next((t for t in gate
                       if isinstance(t.get("ansible.builtin.set_fact"), dict)), None)
    checks.append((
        "the gate's FIRST action sets an empty override (default deny)",
        first_fact is not None
        and first_fact["ansible.builtin.set_fact"].get("dc_model_override_args") == [],
    ))
    checks.append((
        "the gate refuses a supplied grant that fails validation",
        any("fail" in str(k) for t in gate for k in t)
        and "dc_fail_closed" in GATE.read_text(),
    ))

    # --- 3. every agent-invoking harness routes through the gate -------------
    invokers = []
    for path in sorted((ROLE / "tasks").glob("*.yml")):
        text = path.read_text()
        if "'agent', '--agent'" in text or "- agent\n" in text:
            if path.name != GATE.name:
                invokers.append(path)
    for path in invokers:
        text = path.read_text()
        checks.append((f"{path.name} includes the gate",
                       "model_override_gate.yml" in text))
        checks.append((f"{path.name} composes dc_model_override_args into argv",
                       "dc_model_override_args" in text))
    checks.append(("at least one agent-invoking harness is under this contract",
                   len(invokers) > 0))

    # --- 4. synthetic controls: the grant path -------------------------------
    rc, out, err = run_validator(GOOD)
    checks.append(("POSITIVE CONTROL: a well-formed grant is accepted", rc == 0))
    checks.append(("POSITIVE CONTROL: the accepted grant yields the exact model",
                   GOOD["model"] in out))

    negatives = {
        "wrong agent": ({**GOOD, "agentId": "main"}, "dc-research"),
        "self-accepted": ({**GOOD, "acceptedBy": "Claude Code"}, "dc-research"),
        "standing (singleUse false)": ({**GOOD, "singleUse": False}, "dc-research"),
        "wildcard model": ({**GOOD, "model": "ollama-cloud/*"}, "dc-research"),
        "untasked": ({**GOOD, "taskId": "someday"}, "dc-research"),
        "placeholder reason": ({**GOOD, "reason": "because"}, "dc-research"),
        "missing reversal": ({k: v for k, v in GOOD.items() if k != "reversal"}, "dc-research"),
        "smuggled extra field": ({**GOOD, "alsoAllow": "anything"}, "dc-research"),
    }
    for label, (grant, agent) in negatives.items():
        rc, _, _ = run_validator(grant, agent)
        checks.append((f"NEGATIVE CONTROL rejected: {label}", rc != 0))

    # --- 5. replay prevention: single-use must be BEHAVIOURAL ---------------
    shared = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
    Path(shared).unlink()
    rc1, out1, _ = run_validator(GOOD, ledger=shared)
    rc2, _, err2 = run_validator(GOOD, ledger=shared)
    checks.append(("REPLAY: first presentation of a grant is accepted", rc1 == 0))
    checks.append(("REPLAY: the SAME grant presented again is refused", rc2 != 0))
    checks.append(("REPLAY: the refusal names it as already used",
                   "already been used" in err2))
    # Digest is over CONTENT, so a copy under a new name is still spent.
    rc3, _, _ = run_validator(dict(GOOD), ledger=shared)
    checks.append(("REPLAY: a copy of a spent grant is also refused", rc3 != 0))
    # An unreadable ledger must refuse, not assume freshness.
    bad_ledger = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    bad_ledger.write("{ not json"); bad_ledger.close()
    rc4, _, err4 = run_validator(GOOD, ledger=bad_ledger.name)
    checks.append(("REPLAY: an unreadable ledger refuses rather than assuming unused",
                   rc4 != 0 and "ledger unreadable" in err4))

    # --- 6. task binding: taskId must be checked, not merely shaped ----------
    rc5, _, err5 = run_validator(GOOD, task="TASK-999")
    checks.append(("TASK BINDING: a grant for another task is refused", rc5 != 0))
    checks.append(("TASK BINDING: the refusal names both tasks",
                   "TASK-242" in err5 and "TASK-999" in err5))
    rc6, _, err6 = run_validator(GOOD, task="")
    checks.append(("TASK BINDING: no governing task is refused, not waved through",
                   rc6 != 0))
    checks.append(("the gate refuses a grant when no governing task is set",
                   "dc_governing_task" in GATE.read_text()))
    checks.append(("the gate passes a replay ledger to the validator",
                   "dc_model_grant_ledger_path" in GATE.read_text()))

    # --- 7. CONCURRENCY: at-most-once must hold under a race ----------------
    #
    # os.replace() makes the WRITE atomic and does nothing for the
    # read -> check -> append preceding it. Without a lock over the whole
    # transaction, two validations can both read a ledger before either records
    # and both accept the same grant — singleUse would then be at-most-once only
    # when runs happen to be sequential. Sequential tests cannot see this.
    #
    # REPEATED ROUNDS, and that is not belt-and-braces. A single 2-way race
    # caught an unlocked validator only about two times in three: the window is
    # small, so one round is a FLAKY negative control, which would pass a broken
    # validator on a good day. Several rounds with a wider fan-out make the
    # detection reliable without instrumenting the validator for the test.
    # The delay is what makes this a real control. Without it the window is
    # unobservable from a test — process startup dominates the critical section
    # — and the check passes IDENTICALLY with and without the lock. Measured:
    # locked yields 1 acceptance per round, unlocked yields 4.
    RACE_ROUNDS, RACERS = 3, 4
    race_env = dict(os.environ, DC_GRANT_TEST_DELAY_MS="300")
    race_ok, race_detail = True, []
    for rnd in range(RACE_ROUNDS):
        ledger = tempfile.NamedTemporaryFile(suffix=".json", delete=False).name
        Path(ledger).unlink()
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(GOOD, fh)
            grant_path = fh.name

        results: list[int] = []
        errs: list[str] = []
        guard = threading.Lock()

        def attempt():
            proc = subprocess.run(
                [sys.executable, str(VALIDATOR), grant_path, str(SCHEMA),
                 "dc-research", "TASK-242", ledger],
                capture_output=True, text=True, env=race_env)
            with guard:
                results.append(proc.returncode)
                errs.append(proc.stderr)

        threads = [threading.Thread(target=attempt) for _ in range(RACERS)]
        for th in threads:
            th.start()
        for th in threads:
            th.join(timeout=60)

        accepted = results.count(0)
        try:
            final = json.load(open(ledger))
        except Exception:
            final = []
        recorded = len([e for e in final if e.get("taskId") == "TASK-242"])
        if accepted != 1 or recorded != 1:
            race_ok = False
            race_detail.append(f"round {rnd}: {accepted} accepted, {recorded} recorded")
        if not any("already been used" in e for e in errs):
            race_ok = False
            race_detail.append(f"round {rnd}: losers did not report a replay refusal")

    checks.append((f"CONCURRENCY: {RACE_ROUNDS} rounds x {RACERS} simultaneous "
                   f"validations, widened window, each yield EXACTLY ONE "
                   f"acceptance", race_ok))
    for detail in race_detail:
        print(f"        RACE -> {detail}")
    checks.append(("the validator locks the whole critical section",
                   "flock" in VALIDATOR.read_text()))

    # --- 8. reviewer-facing wording -----------------------------------------
    schema_text = SCHEMA.read_text().lower()
    checks.append(("the schema does not overstate constraints as inexpressibility",
                   "cannot be expressed" not in schema_text
                   and "not expressible" not in schema_text))

    # --- 9. the gate refuses before it validates ----------------------------
    gate_names = [x.get("name", "") for x in yaml.safe_load(GATE.read_text())]
    try:
        i_task = next(i for i, n in enumerate(gate_names) if "no governing task" in n)
        i_val = next(i for i, n in enumerate(gate_names) if "Validate the grant" in n)
        ordered = i_task < i_val
    except StopIteration:
        ordered = False
    checks.append(("the gate refuses an unbound run BEFORE invoking the validator",
                   ordered))

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {n}")
    if failed:
        print(f"\n{len(failed)} model-override contract check(s) failed.")
        return 1
    print(f"\nAll {len(checks)} model-override contract checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
