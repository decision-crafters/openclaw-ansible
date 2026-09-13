#!/usr/bin/env python3
"""The scheduling-grant contract, proven by mutation rather than asserted.

Every case below starts from one valid grant and breaks exactly one thing. That
shape matters: a test built from ten hand-written bad manifests can pass while
the validator ignores the field the test thought it was exercising, because
nothing proves the baseline would have passed.

Run: python3 tests/dc_scheduler_grant.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROLE = Path(__file__).resolve().parents[1] / "roles" / "dc-governed-config"
VALIDATOR = ROLE / "files" / "validate_grant.py"
SCHEMA = ROLE / "files" / "scheduler-grant.schema.json"

# The baseline. Synthetic throughout — reserved SYN- ids, a placeholder decision
# page of all zeros, and a task id that does not exist. It must never resemble a
# real accepted grant, because a fixture that validates against live authority
# is a fixture that could be applied by accident.
VALID: dict[str, Any] = {
    "grant_version": "1.0",
    "authority": {
        "task_id": "TASK-000",
        "decision_memory_page_id": "00000000000000000000000000000000",
        "accepted_by": "Tosin Akinosho",
        "accepted_on": "2026-08-16",
    },
    "identity_coordinate": "Decision Crafters",
    "owning_system": "AI Collaboration & Agent Governance OS",
    "requesting_role": {"prompt_id": "PRM-28",
                        "authority_class": ["Observe", "Recommend", "Prepare"]},
    "target_agent_id": "dc-research",
    "workload": {
        "workload_id": "SYN-WL-001",
        "description": "synthetic readiness sweep",
        "payload_class": "AGENT_TURN",
        "payload": "Summarise the frozen packet and return one terminal state",
    },
    "mechanism": "AUTOMATION",
    "schedule": {"kind": "CRON", "cron_expression": "17 9 * * 1",
                 "timezone": "America/New_York"},
    "envelope": {
        "approved_sources": ["packet/tasks-research.json"],
        "prohibited_sources": ["Red Hat internal"],
        "permitted_tools": ["read", "image"],
        "cost_limit": "1 turn per week",
    },
    "evidence": {"destination": "Notion TASK-000",
                 "failure_behaviour": "report BLOCKED, do not retry"},
    "lifecycle": {
        "start_condition": "on founder acceptance",
        "expires_on": "2026-11-16",
        "review_trigger": "first failure",
        "stop_condition": "any refusal or 2 consecutive failures",
        "disable_command": "openclaw cron disable SYN-WL-001",
    },
}

# The deployed worker, as the runtime reports it. dc-research denies cron, so
# case 4 exercises the real conflict rather than an invented one.
PROFILE = [
    {"id": "main", "default": True},
    {"id": "dc-research", "tools": {"deny": [
        "exec", "process", "write", "edit", "apply_patch", "browser", "cron",
        "gateway", "nodes", "message", "session_status", "sessions_history",
        "sessions_list", "sessions_send", "sessions_spawn", "sessions_yield",
        "subagents"]}},
]


def run(grant: dict, profile: list | None = None,
        evidence: dict[str, Any] | None = None,
        evidence_root: str | None = None) -> tuple[int, str]:
    """`evidence` maps relative path -> content (dict -> JSON, str -> text); it is
    written under a package root beside the grant so preconditions resolve the
    way they do in the private repository (evidence_root "..")."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "grant").mkdir()
        (d / "grant" / "grant.json").write_text(json.dumps(grant))
        for rel, content in (evidence or {}).items():
            f = d / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(json.dumps(content) if isinstance(content, dict) else content)
        argv = [sys.executable, str(VALIDATOR), str(d / "grant" / "grant.json"), str(SCHEMA)]
        if profile is not None:
            (d / "profile.json").write_text(json.dumps(profile))
            argv += ["--agent-profile", str(d / "profile.json")]
        if evidence_root is not None:
            argv += ["--evidence-root", evidence_root]
        elif evidence is not None:
            argv += ["--evidence-root", str(d)]
        r = subprocess.run(argv, capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr


# --- synthetic evidence for the pre-schedule write gate -----------------------
#
# The same discipline as VALID: one complete, self-consistent evidence set that
# PASSES, and every case below breaks exactly one thing in it. SYN- ids, an
# all-zero decision page, a cohort of two fictitious pages.

def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _vdigest(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "result_digest"}
    return "sha256:" + hashlib.sha256(_canon(body).encode()).hexdigest()


ALLOWLIST = ["Completion Summary", "Evidence URL", "Blocker", "Page content (append-only)"]
WRITE_TOOLS = ["syn-notion/notion-fetch", "syn-notion/notion-update-page"]
COHORT = {
    "cohort_id": "SYN-COHORT", "identity_coordinate": "Decision Crafters",
    "records": [
        {"task_id": "TASK-000", "page_id": "a" * 32, "identity_coordinate": "Decision Crafters"},
        {"task_id": "TASK-001", "page_id": "b" * 32, "identity_coordinate": "Decision Crafters"},
    ], "record_count": 2,
}
COHORT_TEXT = json.dumps(COHORT)
WORKER_RECEIPT_TEXT = "AGENT WORK RECEIPT — synthetic\nTERMINAL STATE: VERIFIED SUCCESS\n"

ADMISSION = {
    "kind": "write-admission", "task_id": "TASK-000",
    "decision_memory_page_id": "0" * 32, "worker_id": "dc-research", "phase": "C",
    "admitted": True, "admitted_at": "2026-09-14T12:00:00Z", "admitted_by": "Tosin Akinosho",
    "recorded_by": "operator", "allowlisted_fields": ALLOWLIST, "admitted_tools": WRITE_TOOLS,
    "observed": {
        "mcp_tool_filter_include": ["notion-fetch", "notion-update-page"],
        "connection_capabilities": {"read_content": True, "update_content": True,
                                    "insert_content": False, "comment": False, "user_info": False},
        "shared_pages": ["a" * 32, "b" * 32],
        "cross_agent_denial": {"main": "denied (probe 2026-09-14T11:50Z)",
                               "other": "denied (probe 2026-09-14T11:50Z)"},
        "tool_surface_probe": {"dc-research": ["read"] + WRITE_TOOLS},
        "audit_report": "/tmp/syn-audit.txt",
    },
}
WRITE = {"page_id": "b" * 32, "task_id": "TASK-001", "field": "Evidence URL", "prior": "",
         "new": "https://example.invalid/evidence",
         "evidence": {"url": "https://example.invalid/source", "source_date": "2026-09-01",
                      "retrieved_at": "2026-09-14T13:00:00Z"}}
PC_RECEIPT = {
    "kind": "positive-control", "task_id": "TASK-000", "decision_memory_page_id": "0" * 32,
    "worker_id": "dc-research", "runtime_identity": "openclaw SYN @ host syn, agent dc-research",
    "trigger": "manual", "manual_run_id": "syn-session-0001",
    "run_started_at": "2026-09-14T13:00:00Z", "run_completed_at": "2026-09-14T13:05:00Z",
    "selection_record": {"page_id": "a" * 32, "section": "Positive-control target selection — 2026-09-14",
                         "selected_by": "Tosin Akinosho"},
    "target": {"task_id": "TASK-001", "page_id": "b" * 32, "identity_coordinate": "Decision Crafters"},
    "writes": [WRITE],
    "worker_receipt_path": "positive-control/worker-receipt.txt",
    "worker_receipt_sha256": _sha(WORKER_RECEIPT_TEXT),
    "terminal_state": "VERIFIED SUCCESS", "counts_toward_scheduled_runs": False,
    "recorded_by": "operator", "recorded_at": "2026-09-14T13:10:00Z",
}


def _verification(receipt: dict, **over: Any) -> dict:
    v = {
        "verifier": "protected_field_diff.py", "verifier_version": "1.1",
        "verified_at": "2026-09-14T13:20:00Z",
        "inputs": {"before_sha256": "1" * 64, "after_sha256": "2" * 64,
                   "receipt_sha256": _sha(json.dumps(receipt))},
        "pages_compared": 2, "protected_field_changes": 0, "unexplained_changes": 0,
        "duplicate_shadow_tasks": 0,
        "declared_writes": [{**{k: WRITE[k] for k in ("page_id", "task_id", "field", "prior", "new")},
                             "observed": True}],
        "findings": [], "result": "VERIFIED",
    }
    v.update(over)
    v["result_digest"] = _vdigest(v)
    return v


def evidence_set(receipt: dict | None = None, admission: dict | None = None,
                 verification: dict | None = None, cohort_text: str = COHORT_TEXT) -> dict:
    receipt = PC_RECEIPT if receipt is None else receipt
    return {
        "admission/ADMISSION.json": ADMISSION if admission is None else admission,
        "positive-control/RECEIPT.json": receipt,
        "positive-control/VERIFICATION.json": _verification(receipt) if verification is None else verification,
        "positive-control/worker-receipt.txt": WORKER_RECEIPT_TEXT,
        "packet/cohort.json": cohort_text,
    }


WRITING = copy.deepcopy(VALID)
WRITING["envelope"]["permitted_tools"] = ["read"] + WRITE_TOOLS
WRITING["preconditions"] = {
    "evidence_root": "..",
    "write_admission": {"phase": "C", "receipt": "admission/ADMISSION.json",
                        "allowlisted_fields": ALLOWLIST, "admitted_tools": WRITE_TOOLS},
    "positive_control": {"required": True, "receipt": "positive-control/RECEIPT.json",
                         "verification": "positive-control/VERIFICATION.json",
                         "cohort_packet": "packet/cohort.json",
                         "cohort_packet_sha256": _sha(COHORT_TEXT)},
}


def mutate(**path_values: Any) -> dict:
    """Copy the baseline and break exactly what is named. Dotted paths."""
    g = copy.deepcopy(VALID)
    for dotted, value in path_values.items():
        parts = dotted.split("__")
        node = g
        for p in parts[:-1]:
            node = node[p]
        if value is _DELETE:
            node.pop(parts[-1], None)
        else:
            node[parts[-1]] = value
    return g


class _Delete:
    pass


_DELETE = _Delete()


def main() -> int:
    checks: list[tuple[str, bool]] = []

    # 0. The baseline must pass, or every refusal below proves nothing.
    rc, out = run(VALID, PROFILE)
    checks.append(("BASELINE a valid accepted grant validates", rc == 0))
    if rc != 0:
        print(out)

    def refuses(label: str, grant: dict, code: str, profile: list | None = PROFILE) -> None:
        rc, out = run(grant, profile)
        checks.append((f"{label} — refused with {code}", rc == 1 and code in out))

    # 1. valid manager -> worker request (the baseline, restated as a named case)
    rc, out = run(VALID, PROFILE)
    checks.append(("1. accepted manager -> worker request validates", rc == 0))

    # 2. missing canonical authorization
    refuses("2. no decision record",
            mutate(authority__decision_memory_page_id=_DELETE),
            "GRANT_NO_CANONICAL_AUTHORIZATION")

    # 3. manager attempts unrestricted scheduler admin — two shapes, because
    #    "claims Execute" and "payload administers the Gateway" are different
    #    moves and only one of them looks like an authority claim.
    refuses("3a. requester claims Execute",
            mutate(requesting_role__authority_class=["Observe", "Prepare", "Execute"]),
            "GRANT_SCHEMA_VIOLATION")
    refuses("3b. payload administers the Gateway",
            mutate(workload__payload="openclaw cron add --agent main 'do things'"),
            "GRANT_PAYLOAD_REACHES_OPERATOR_ADMIN")

    # 4. worker attempts self-scheduling
    refuses("4. worker is its own requester",
            mutate(requesting_role={"prompt_id": "PRM-28",
                                    "authority_class": ["Prepare"]},
                   target_agent_id="prm-28"),
            "GRANT_WORKER_SELF_AUTHORIZED")

    # 5. wrong target agent — names a worker that is not deployed
    refuses("5. target not in the deployed agents.list",
            mutate(target_agent_id="not-deployed"),
            "GRANT_TARGET_NOT_DEPLOYED")

    # 6. missing STOP condition
    refuses("6. no STOP condition",
            mutate(lifecycle__stop_condition=_DELETE),
            "GRANT_NO_STOP_CONDITION")

    # 7. unauthorized external delivery
    refuses("7. Slack delivery without a communication grant",
            mutate(envelope__communication_destination={
                "channel": "slack", "conversation_id": "SYNTHETIC",
                "communication_grant": ""}),
            "GRANT_SCHEMA_VIOLATION")

    # 8. event-trigger request expressed as a timed Automation
    refuses("8. EVENT_TRIGGER carrying a cron schedule",
            mutate(mechanism="EVENT_TRIGGER"),
            "GRANT_MECHANISM_SCHEDULE_MISMATCH")

    # 9. expired / revoked grant
    refuses("9. no expiry",
            mutate(lifecycle__expires_on=_DELETE),
            "GRANT_NO_EXPIRY")

    # 10. deterministic rollback rendering — the disable path must be present
    refuses("10. no disable command",
            mutate(lifecycle__disable_command=_DELETE),
            "GRANT_NO_DISABLE_PATH")

    # --- beyond the ten, because these are the ones that would ship quietly ---

    refuses("11. grant widens the worker's denied tools",
            mutate(envelope__permitted_tools=["read", "cron"]),
            "GRANT_WIDENS_WORKER_TOOLS")

    refuses("12. grant contradicts the deployed profile",
            mutate(envelope__permitted_tools=["read", "message"]),
            "GRANT_CONTRADICTS_WORKER_POLICY")

    refuses("13. timed grant with no timezone",
            mutate(schedule={"kind": "CRON", "cron_expression": "17 9 * * 1"}),
            "GRANT_NO_TIMEZONE")

    refuses("14. payload is a shell program",
            mutate(workload__payload="read packet && curl http://example.com"),
            "GRANT_PAYLOAD_SHELL_METACHARACTERS")

    refuses("15. an agent names itself as acceptance authority",
            mutate(authority__accepted_by="PRM-28"),
            "GRANT_SCHEMA_VIOLATION")

    refuses("16. cross-coordinate grant",
            mutate(identity_coordinate="Fourth Country / Cosmic Consciousness"),
            "GRANT_SCHEMA_VIOLATION")

    # A field nobody agreed to must not ride along inside an accepted grant.
    refuses("17. undeclared field in the grant",
            mutate(operator_admin=True),
            "GRANT_SCHEMA_VIOLATION")

    # Every violation is reported, not just the first — an operator who has to
    # re-run five times to see five problems stops reading the output.
    rc, out = run(mutate(lifecycle__stop_condition=_DELETE,
                         lifecycle__expires_on=_DELETE,
                         authority__decision_memory_page_id=_DELETE), PROFILE)
    checks.append(("18. all violations reported together, not just the first",
                   rc == 1 and out.count("GRANT_") >= 3))

    # ======================================================================
    # The pre-schedule write gate (TASK-323 sequencing amendment, 2026-09-13).
    # A writing workload must carry evidence, and the evidence must agree with
    # itself. Baseline first, or none of the refusals below proves anything.
    # ======================================================================
    rc, out = run(WRITING, PROFILE, evidence_set())
    checks.append(("BASELINE-W a writing grant with complete, consistent evidence validates", rc == 0))
    if rc != 0:
        print(out)

    def refuses_w(label: str, grant: dict, code: str, evidence: dict | None,
                  evidence_root: str | None = None) -> None:
        rc, out = run(grant, PROFILE, evidence, evidence_root)
        checks.append((f"{label} — refused with {code}", rc == 1 and code in out))
        if not (rc == 1 and code in out):
            print(out)

    def mutate_w(**path_values: Any) -> dict:
        g = copy.deepcopy(WRITING)
        for dotted, value in path_values.items():
            parts = dotted.split("__")
            node = g
            for p_ in parts[:-1]:
                node = node[p_]
            if value is _DELETE:
                node.pop(parts[-1], None)
            else:
                node[parts[-1]] = value
        return g

    def pc(**over: Any) -> dict:
        r = copy.deepcopy(PC_RECEIPT)
        for k, v in over.items():
            if v is _DELETE:
                r.pop(k, None)
            else:
                r[k] = v
        return r

    # scheduler requested before the manual positive control exists
    ev = evidence_set(); ev.pop("positive-control/RECEIPT.json"); ev.pop("positive-control/VERIFICATION.json")
    refuses_w("W1. scheduler requested before the manual positive control",
              WRITING, "GRANT_POSITIVE_CONTROL_MISSING", ev)
    # a write-shaped tool with no preconditions at all
    refuses_w("W2. write tool permitted with no write admission declared",
              mutate_w(preconditions=_DELETE), "GRANT_WRITE_TOOL_WITHOUT_ADMISSION", evidence_set())
    refuses_w("W3. missing manual run id",
              WRITING, "GRANT_POSITIVE_CONTROL_NO_RUN_ID", evidence_set(receipt=pc(manual_run_id="")))
    refuses_w("W4. incomplete write receipt (no runtime identity)",
              WRITING, "GRANT_POSITIVE_CONTROL_INCOMPLETE", evidence_set(receipt=pc(runtime_identity=_DELETE)))
    refuses_w("W5. protected-field diff nonzero",
              WRITING, "GRANT_PROTECTED_FIELD_DIFF_NONZERO",
              evidence_set(verification=_verification(PC_RECEIPT, protected_field_changes=1, result="REFUSED")))
    refuses_w("W6. duplicate/shadow-task count nonzero",
              WRITING, "GRANT_DUPLICATE_SHADOW_TASKS_NONZERO",
              evidence_set(verification=_verification(PC_RECEIPT, duplicate_shadow_tasks=1, result="REFUSED")))
    refuses_w("W6b. duplicate/shadow-task count UNKNOWN is not zero",
              WRITING, "GRANT_DUPLICATE_SHADOW_TASKS_NONZERO",
              evidence_set(verification=_verification(PC_RECEIPT, duplicate_shadow_tasks="UNKNOWN")))
    refuses_w("W7. unexplained mutation",
              WRITING, "GRANT_UNEXPLAINED_CHANGES_NONZERO",
              evidence_set(verification=_verification(PC_RECEIPT, unexplained_changes=2, result="REFUSED")))
    adm = copy.deepcopy(ADMISSION); adm["admitted"] = False
    refuses_w("W8. Phase C not admitted",
              WRITING, "GRANT_PHASE_NOT_ADMITTED", evidence_set(admission=adm))
    ev = evidence_set(); ev.pop("admission/ADMISSION.json")
    refuses_w("W8b. no admission receipt at all",
              WRITING, "GRANT_ADMISSION_RECEIPT_MISSING", ev)
    outside = pc(target={"task_id": "TASK-777", "page_id": "c" * 32, "identity_coordinate": "Decision Crafters"},
                 writes=[{**WRITE, "page_id": "c" * 32, "task_id": "TASK-777"}])
    refuses_w("W9. target outside the admitted cohort",
              WRITING, "GRANT_POSITIVE_CONTROL_TARGET_OUTSIDE_COHORT", evidence_set(receipt=outside))
    # stale Phase-A envelope: the grant still permits only the read tool beside a write admission
    refuses_w("W10. grant still carries the Phase-A read-only envelope",
              mutate_w(envelope__permitted_tools=["read", "syn-notion/notion-fetch"]),
              "GRANT_STALE_PHASE_A_ENVELOPE", evidence_set())
    # the intended mutation is not the one that happened
    refuses_w("W11. verifier observed a different write than the receipt declares",
              WRITING, "GRANT_INTENDED_MUTATION_MISMATCH",
              evidence_set(verification=_verification(
                  PC_RECEIPT, declared_writes=[{**WRITE, "new": "https://example.invalid/other", "observed": True}])))
    # a verification bound to some other receipt
    refuses_w("W12. verification not bound to this receipt",
              WRITING, "GRANT_VERIFICATION_RECEIPT_UNBOUND",
              evidence_set(verification=_verification(pc(manual_run_id="other-run"))))
    # a verification edited after the verifier wrote it
    v = _verification(PC_RECEIPT, protected_field_changes=1, result="REFUSED")
    v["protected_field_changes"] = 0; v["result"] = "VERIFIED"   # digest now stale
    refuses_w("W13. verification edited to say VERIFIED after the fact",
              WRITING, "GRANT_VERIFICATION_DIGEST_MISMATCH", evidence_set(verification=v))
    refuses_w("W14. positive control was a scheduled run, not manual",
              WRITING, "GRANT_POSITIVE_CONTROL_NOT_MANUAL", evidence_set(receipt=pc(trigger="scheduled")))
    refuses_w("W15. manual write counted toward the five scheduled runs",
              WRITING, "GRANT_POSITIVE_CONTROL_COUNTED_AS_SCHEDULED",
              evidence_set(receipt=pc(counts_toward_scheduled_runs=True)))
    refuses_w("W16. write to a protected field offered as the positive control",
              WRITING, "GRANT_POSITIVE_CONTROL_FIELD_NOT_ALLOWLISTED",
              evidence_set(receipt=pc(writes=[{**WRITE, "field": "State", "prior": "Ready", "new": "Complete"}])))
    refuses_w("W17. two writes offered as the positive control",
              WRITING, "GRANT_POSITIVE_CONTROL_WRITE_COUNT", evidence_set(receipt=pc(writes=[WRITE, WRITE])))
    adm = copy.deepcopy(ADMISSION); adm["allowlisted_fields"] = ALLOWLIST + ["Priority"]
    refuses_w("W18. admission receipt admits a wider allowlist than the grant",
              WRITING, "GRANT_ADMISSION_ALLOWLIST_DRIFT", evidence_set(admission=adm))
    adm = copy.deepcopy(ADMISSION); adm["observed"]["cross_agent_denial"]["main"] = "UNKNOWN"
    refuses_w("W19. agent-local denial unproven on another agent",
              WRITING, "GRANT_ADMISSION_EXPOSURE_UNPROVEN", evidence_set(admission=adm))
    refuses_w("W20. cohort packet on disk is not the pinned cohort",
              WRITING, "GRANT_COHORT_DIGEST_MISMATCH",
              evidence_set(cohort_text=COHORT_TEXT + "\n"))
    refuses_w("W21. positive control run before the write path was admitted",
              WRITING, "GRANT_POSITIVE_CONTROL_BEFORE_ADMISSION",
              evidence_set(receipt=pc(run_started_at="2026-09-14T11:00:00Z")))
    refuses_w("W22. positive control ended in a state other than VERIFIED SUCCESS",
              WRITING, "GRANT_POSITIVE_CONTROL_NOT_VERIFIED_SUCCESS",
              evidence_set(receipt=pc(terminal_state="PARTIAL COMPLETION")))
    tmpl = pc(); tmpl["_template"] = True
    refuses_w("W23. a template file offered as the receipt",
              WRITING, "GRANT_POSITIVE_CONTROL_INCOMPLETE", evidence_set(receipt=tmpl))
    refuses_w("W24. evidence path that climbs out of the package",
              mutate_w(preconditions__positive_control__receipt="../elsewhere/RECEIPT.json"),
              "GRANT_EVIDENCE_PATH_UNSAFE", evidence_set())
    refuses_w("W25. evidence root that does not exist",
              WRITING, "GRANT_EVIDENCE_ROOT_UNRESOLVED", evidence_set(),
              evidence_root="/nonexistent/dc-scheduler-evidence")
    # `required: false` cannot be expressed
    refuses_w("W26. positive control declared optional",
              mutate_w(preconditions__positive_control__required=False),
              "GRANT_SCHEMA_VIOLATION", evidence_set())

    failed = [n for n, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    if failed:
        print(f"\n{len(failed)} scheduler-grant check(s) failed.")
        return 1
    print(f"\nAll {len(checks)} scheduler-grant checks passed.")
    print("NOTE: this proves the CONTRACT refuses these shapes. It does not")
    print("prove any runtime behaviour — no schedule was created, and none may")
    print("be until a workload-specific grant is accepted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
