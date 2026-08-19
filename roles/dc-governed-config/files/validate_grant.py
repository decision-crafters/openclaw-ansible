#!/usr/bin/env python3
"""Validate a scheduling grant. Fails closed on everything it cannot confirm.

    validate_grant.py <grant.json> <schema.json> [--agent-profile <agents-list.json>]

Exit 0 = the grant is well-formed AND every policy rule passed.
Exit 1 = refused; every reason is printed, not just the first.
Exit 2 = usage or unreadable input.

WHY A SECOND VALIDATOR EXISTS BESIDE THE SCHEMA
-----------------------------------------------

The schema pins shape. Everything below is a CROSS-FIELD rule, which JSON Schema
cannot express: that the schedule matches the mechanism, that a communication
destination carries its own separate grant, that the permitted tools do not
widen what the target worker's own profile denies, that nothing in the payload
reaches for operator administration.

This mirrors the split already used for config: `validate_overlay.py` is a cheap
early filter and `openclaw config patch --dry-run` is the authority. Here there
is no runtime authority to defer to — nothing validates a grant but this file —
so it refuses on anything it cannot positively confirm.

THE POSTURE THIS ENFORCES
-------------------------

`NO_SCHEDULER` is the default (TASK-229, accepted 2026-08-16). Agent admission,
tool access, communication binding, and the ability to perform the underlying
work confer NO scheduling authority. A manager agent may Observe, Recommend and
Prepare a request; creating or activating a schedule requires a separately
accepted bounded grant, applied by an operator path.

So the first check is authority, and it is the one that fails today: no accepted
scheduling grant exists in Decision Memory. Every real manifest is refused until
the founder creates one. The apply path is complete and simply cannot pass.
That is the safety property, not an unfinished edge.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Verbs and shapes that mean "this grant is reaching past the workload".
#
# Screened in the PAYLOAD, because that is the field an operator pastes into and
# the one a manager agent composes. A grant whose payload shells out has stopped
# being a bounded workload whatever the rest of the manifest says.
_OPERATOR_ADMIN = (
    "operator.admin", "gateway ", "openclaw gateway", "config patch",
    "config set", "config unset", "cron create", "cron add", "cron edit",
    "cron rm", "cron remove", "hooks install", "agents add", "agents delete",
    "sudo ", "systemctl", "runuser", "chmod ", "chown ",
)
_SHELL_METACHARS = ("&&", "||", ";", "|", "`", "$(", ">", "<", "\n")

# Mechanism -> the schedule kinds that mechanism may legally carry.
_MECHANISM_KINDS = {
    "AUTOMATION": {"CRON"},
    "HEARTBEAT": {"INTERVAL"},
    "EVENT_TRIGGER": {"EVENT"},
}

# Tools a worker must never receive THROUGH a scheduling grant. Scheduling a
# workload is not an occasion to widen what it may do.
_NEVER_GRANTED = {
    "exec", "process", "write", "edit", "apply_patch", "browser",
    "gateway", "nodes", "cron", "heartbeat_respond", "subagents",
}


def _fail(code: str, detail: str) -> str:
    return f"{code}: {detail}"


def check_schema(grant: dict, schema: dict) -> list[str]:
    """Shape first. Without jsonschema, refuse — never fall through to policy.

    A missing library must not silently downgrade this to a policy-only check
    that prints fewer refusals and exits the same way.
    """
    try:
        import jsonschema  # noqa: PLC0415 - guarded so the failure can be explained
    except ImportError:
        return [_fail("GRANT_VALIDATOR_UNAVAILABLE",
                      "python3-jsonschema is not installed. Refusing rather than "
                      "validating policy against an unvalidated shape.")]

    validator = jsonschema.Draft202012Validator(schema)
    return [
        _fail("GRANT_SCHEMA_VIOLATION",
              f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}")
        for e in sorted(validator.iter_errors(grant), key=lambda e: list(e.absolute_path))
    ]


def check_policy(grant: dict, profile: dict | None) -> list[str]:
    """Every cross-field rule. Returns ALL violations, never just the first.

    Stopping at the first refusal turns one fix into one round trip each; an
    operator who has to re-run five times learns to stop reading the output.
    """
    out: list[str] = []
    g = grant.get

    # --- authority ------------------------------------------------------------
    authority = g("authority") or {}
    if not authority.get("decision_memory_page_id"):
        out.append(_fail(
            "GRANT_NO_CANONICAL_AUTHORIZATION",
            "authority.decision_memory_page_id is absent. A task id is not "
            "acceptance, and NO_SCHEDULER is the default posture."))
    if authority.get("accepted_by") != "Tosin Akinosho":
        out.append(_fail(
            "GRANT_NOT_FOUNDER_ACCEPTED",
            "authority.accepted_by must be the sole acceptance authority. An "
            "agent naming itself here is the failure this contract prevents."))

    # --- requesting role: prepare, never execute ------------------------------
    role = g("requesting_role") or {}
    classes = set(role.get("authority_class") or [])
    if "Execute" in classes:
        out.append(_fail(
            "GRANT_REQUESTER_CLAIMS_EXECUTE",
            "the requesting role claims Execute. A manager prepares a request; "
            "creation and activation belong to the scheduler authority."))
    if not classes:
        out.append(_fail("GRANT_REQUESTER_NO_AUTHORITY",
                         "requesting_role.authority_class is empty."))

    # --- self-scheduling ------------------------------------------------------
    #
    # The worker must not be the requester. An agent that prepares its own
    # persistence has self-authorized, whatever the rest of the manifest says.
    if role.get("prompt_id") and g("target_agent_id"):
        if str(role.get("prompt_id")).lower() == str(g("target_agent_id")).lower():
            out.append(_fail(
                "GRANT_WORKER_SELF_AUTHORIZED",
                "the requesting role and the target worker are the same. "
                "Self-scheduling is denied by default."))

    # --- mechanism vs schedule ------------------------------------------------
    mechanism = g("mechanism")
    schedule = g("schedule") or {}
    kind = schedule.get("kind")
    allowed = _MECHANISM_KINDS.get(mechanism, set())
    if mechanism and kind and kind not in allowed:
        out.append(_fail(
            "GRANT_MECHANISM_SCHEDULE_MISMATCH",
            f"mechanism {mechanism} requires schedule.kind in "
            f"{sorted(allowed)}, got {kind!r}. An event-driven workload "
            f"expressed as a timed job fires on a clock nobody chose."))

    if kind == "CRON" and not schedule.get("cron_expression"):
        out.append(_fail("GRANT_NO_CADENCE", "schedule.kind is CRON with no cron_expression."))
    if kind == "INTERVAL" and not schedule.get("interval"):
        out.append(_fail("GRANT_NO_CADENCE", "schedule.kind is INTERVAL with no interval."))
    if kind == "EVENT" and not schedule.get("event_source"):
        out.append(_fail("GRANT_NO_TRIGGER", "schedule.kind is EVENT with no event_source."))
    if kind in ("CRON", "INTERVAL") and not schedule.get("timezone"):
        out.append(_fail(
            "GRANT_NO_TIMEZONE",
            "a timed grant carries no timezone. Absent does not mean UTC — it "
            "means the Gateway host's timezone, which is invisible here."))

    # --- lifecycle ------------------------------------------------------------
    lifecycle = g("lifecycle") or {}
    if not lifecycle.get("stop_condition"):
        out.append(_fail(
            "GRANT_NO_STOP_CONDITION",
            "no STOP condition. A schedule fires until somebody removes it, so "
            "a limit recorded only in the authorization is a limit nothing "
            "enforces."))
    if not lifecycle.get("disable_command"):
        out.append(_fail("GRANT_NO_DISABLE_PATH",
                         "no disable_command. An untested stop path is a claim."))
    if not lifecycle.get("expires_on"):
        out.append(_fail("GRANT_NO_EXPIRY", "no expires_on."))

    # --- communication is a separate grant ------------------------------------
    envelope = g("envelope") or {}
    comms = envelope.get("communication_destination")
    if comms and not comms.get("communication_grant"):
        out.append(_fail(
            "GRANT_COMMS_WITHOUT_AUTHORITY",
            "a communication destination is present with no separate "
            "communication grant. Scheduling authority does not carry delivery "
            "authority."))

    # --- event-trigger specific controls --------------------------------------
    if mechanism == "EVENT_TRIGGER":
        if envelope.get("allow_request_session_key") is not False:
            out.append(_fail(
                "GRANT_EVENT_SESSION_KEY_UNPINNED",
                "allow_request_session_key must be present and false. A caller "
                "choosing its own session key can address a session it was "
                "never granted."))
        if not envelope.get("allowed_session_key_prefixes"):
            out.append(_fail("GRANT_EVENT_NO_KEY_PREFIXES",
                             "EVENT_TRIGGER with no allowed_session_key_prefixes."))

    # --- the grant may not widen the worker -----------------------------------
    permitted = set(envelope.get("permitted_tools") or [])
    reaching = sorted(permitted & _NEVER_GRANTED)
    if reaching:
        out.append(_fail(
            "GRANT_WIDENS_WORKER_TOOLS",
            f"permitted_tools requests {reaching}. Scheduling a workload is not "
            f"an occasion to widen what it may do."))

    if profile is not None:
        entry = next((e for e in profile.get("agents", [])
                      if e.get("id") == g("target_agent_id")), None)
        if entry is None:
            out.append(_fail(
                "GRANT_TARGET_NOT_DEPLOYED",
                f"target_agent_id {g('target_agent_id')!r} is not present in the "
                f"deployed agents.list. A grant cannot name a worker that does "
                f"not exist."))
        else:
            denied = set(entry.get("tools", {}).get("deny", []))
            conflict = sorted(permitted & denied)
            if conflict:
                out.append(_fail(
                    "GRANT_CONTRADICTS_WORKER_POLICY",
                    f"permitted_tools {conflict} are denied by the deployed "
                    f"profile for {g('target_agent_id')}. The grant would have "
                    f"to widen the worker to run."))

    # --- payload reach --------------------------------------------------------
    payload = str((g("workload") or {}).get("payload") or "")
    low = payload.lower()
    admin_hits = sorted({v.strip() for v in _OPERATOR_ADMIN if v in low})
    if admin_hits:
        out.append(_fail(
            "GRANT_PAYLOAD_REACHES_OPERATOR_ADMIN",
            f"payload contains operator-administration verbs {admin_hits}. A "
            f"scheduled workload may not administer the Gateway that runs it."))
    shell_hits = sorted({c for c in _SHELL_METACHARS if c in payload})
    if shell_hits:
        out.append(_fail(
            "GRANT_PAYLOAD_SHELL_METACHARACTERS",
            f"payload contains {shell_hits}. A bounded payload is one command, "
            f"not a shell program."))

    return out


def _load(path: Path, label: str) -> tuple[Any, str | None]:
    try:
        return json.loads(path.read_text()), None
    except FileNotFoundError:
        return None, f"{label} not found: {path}"
    except json.JSONDecodeError as exc:
        return None, f"{label} is not valid JSON: {exc}"
    except OSError as exc:
        return None, f"{label} unreadable: {exc}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("grant")
    ap.add_argument("schema")
    ap.add_argument("--agent-profile", default=None,
                    help="deployed agents.list JSON, for cross-checking the worker")
    args = ap.parse_args()

    grant, err = _load(Path(args.grant), "grant")
    if err:
        print(err, file=sys.stderr)
        return 2
    schema, err = _load(Path(args.schema), "schema")
    if err:
        print(err, file=sys.stderr)
        return 2

    profile = None
    if args.agent_profile:
        raw, err = _load(Path(args.agent_profile), "agent profile")
        if err:
            print(err, file=sys.stderr)
            return 2
        # Accept either a bare agents.list array or a wrapper object.
        profile = {"agents": raw} if isinstance(raw, list) else raw

    if not isinstance(grant, dict):
        print("grant root must be an object", file=sys.stderr)
        return 2

    violations = check_schema(grant, schema) + check_policy(grant, profile)

    if violations:
        print(f"REFUSED — {len(violations)} violation(s):")
        for v in violations:
            print(f"  {v}")
        print("\nNothing has been scheduled. NO_SCHEDULER remains in force.")
        return 1

    print("GRANT VALID — shape and policy checks passed.")
    print("This says the grant is well-formed and internally consistent.")
    print("It does NOT create, activate or authorize a schedule; the apply path")
    print("is separately gated and requires an accepted decision record.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
