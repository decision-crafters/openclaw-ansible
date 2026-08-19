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
  4. The schema makes over-broad grants INEXPRESSIBLE, not merely invalid:
     self-acceptance, standing grants and wildcard models are const/pattern
     violations.

Validated by synthetic controls only. No alternate model is ever invoked.
"""
from __future__ import annotations

import json
import subprocess
import sys
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


def run_validator(grant: dict, agent: str = "dc-research"):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(grant, fh)
        path = fh.name
    p = subprocess.run([sys.executable, str(VALIDATOR), path, str(SCHEMA), agent],
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
