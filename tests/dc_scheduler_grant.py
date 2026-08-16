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


def run(grant: dict, profile: list | None = None) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "grant.json").write_text(json.dumps(grant))
        argv = [sys.executable, str(VALIDATOR), str(d / "grant.json"), str(SCHEMA)]
        if profile is not None:
            (d / "profile.json").write_text(json.dumps(profile))
            argv += ["--agent-profile", str(d / "profile.json")]
        r = subprocess.run(argv, capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr


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
