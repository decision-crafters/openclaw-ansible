#!/usr/bin/env python3
"""Validate a scheduling grant. Fails closed on everything it cannot confirm.

    validate_grant.py <grant.json> <schema.json> [--agent-profile <agents-list.json>]
                      [--evidence-root <dir>]

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

THE PRE-SCHEDULE WRITE GATE (added 2026-09-13)
----------------------------------------------

A workload that WRITES canonical records earns a second, later gate before it
may recur. The Founder sequencing amendment of 2026-09-13 (TASK-323, Decision
Memory 3da2bfbf792181fb961eebca635cb647) requires, before any recurring job:
the already-approved write allowlist operationally admitted; one manually
triggered positive-control write against a deliberately selected low-risk
task; its complete receipt; and independent verification of the intended
mutation, zero protected-field mutations, zero duplicate/shadow tasks and zero
unexplained changes.

This validator enforces that from EVIDENCE, not from a flag. If the grant
permits a write-shaped tool it must carry `preconditions.write_admission` and
`preconditions.positive_control`; each names governed evidence files which
are opened (under --evidence-root, or beside the grant) and cross-checked
against the grant, against each other, and against the pinned cohort packet.
The verification file is bound to the receipt by digest and carries its own
result digest, so a human cannot satisfy the gate by typing PASS anywhere.
Any file missing, incomplete, inconsistent or refusing is a refusal here.
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


# Tokens that make a tool name "write-shaped". Token match on the name split at
# non-alphanumerics, so `notion-update-page` and `mcp__x__create_page` both hit
# and `read` / `notion-fetch` do not. A tool that can mutate a canonical record
# may not ride into a schedule without a write admission and a positive control.
_WRITE_TOKENS = {
    "update", "create", "insert", "delete", "move", "patch", "write", "edit",
    "append", "duplicate", "remove", "archive", "publish", "send", "set",
}

# Keys a positive-control receipt must carry, and the keys of its single write.
# The canonical list (TASK-323 criterion 6 / amendment 2026-09-13): task ID,
# source evidence, changed field, old/new value or append receipt, runtime
# identity, manual run ID, authority source.
_PC_REQUIRED = (
    "kind", "task_id", "decision_memory_page_id", "worker_id", "runtime_identity",
    "trigger", "manual_run_id", "run_started_at", "run_completed_at",
    "selection_record", "target", "writes", "worker_receipt_path",
    "worker_receipt_sha256", "terminal_state", "counts_toward_scheduled_runs",
    "recorded_by", "recorded_at",
)
_PC_WRITE_REQUIRED = ("page_id", "task_id", "field", "prior", "new", "evidence")
_PC_EVIDENCE_REQUIRED = ("url", "source_date", "retrieved_at")
_ADM_REQUIRED = (
    "kind", "task_id", "decision_memory_page_id", "worker_id", "phase", "admitted",
    "admitted_at", "admitted_by", "recorded_by", "allowlisted_fields",
    "admitted_tools", "observed",
)
_ADM_OBSERVED_REQUIRED = (
    "mcp_tool_filter_include", "connection_capabilities", "shared_pages",
    "cross_agent_denial", "tool_surface_probe", "audit_report",
)
_VER_REQUIRED = (
    "verifier", "verified_at", "inputs", "pages_compared", "protected_field_changes",
    "unexplained_changes", "duplicate_shadow_tasks", "declared_writes", "result",
    "result_digest",
)


def _fail(code: str, detail: str) -> str:
    return f"{code}: {detail}"


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def verification_digest(doc: dict) -> str:
    """The verifier's self-digest: sha256 of the canonical JSON of everything but
    `result_digest`. The verifier (protected_field_diff.py) computes it the same
    way; a verification file edited after the fact no longer matches."""
    import hashlib  # noqa: PLC0415
    body = {k: v for k, v in doc.items() if k != "result_digest"}
    return "sha256:" + hashlib.sha256(_canon(body).encode()).hexdigest()


def _sha256_file(path: Path) -> str:
    import hashlib  # noqa: PLC0415
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_placeholder(v: Any) -> bool:
    """Template values look like `<...>`; an empty string is also not evidence."""
    if v is None:
        return True
    if isinstance(v, str):
        t = v.strip()
        return t == "" or (t.startswith("<") and t.endswith(">"))
    return False


def _missing(doc: dict, keys: tuple[str, ...]) -> list[str]:
    return [k for k in keys if k not in doc or _is_placeholder(doc.get(k))]


def _ts(v: Any):
    """ISO 8601 -> aware datetime, or None when it does not parse."""
    from datetime import datetime, timezone  # noqa: PLC0415
    if not isinstance(v, str) or _is_placeholder(v):
        return None
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _write_shaped(tool: str) -> bool:
    return bool(set(re.split(r"[^a-z0-9]+", tool.lower())) & _WRITE_TOKENS)


def _safe_rel(path: str) -> bool:
    """Evidence paths are plain relative paths: no absolute, no `..` component."""
    if not isinstance(path, str) or not path or path.startswith("/"):
        return False
    return ".." not in Path(path).parts


def _load_evidence(root: Path, rel: str, label: str, out: list[str]) -> dict | None:
    if not _safe_rel(rel):
        out.append(_fail("GRANT_EVIDENCE_PATH_UNSAFE",
                         f"{label} path {rel!r} must be relative with no '..' component."))
        return None
    path = root / rel
    if not path.is_file():
        out.append(_fail(f"GRANT_{label}_MISSING",
                         f"{rel} is not present under {root}. Evidence that does not "
                         f"exist is not evidence; nothing is inferred in its place."))
        return None
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        out.append(_fail(f"GRANT_{label}_MISSING", f"{rel} unreadable: {exc}"))
        return None
    if not isinstance(doc, dict):
        out.append(_fail(f"GRANT_{label}_INCOMPLETE", f"{rel} root must be an object."))
        return None
    if doc.get("_template") is True:
        out.append(_fail(f"GRANT_{label}_INCOMPLETE",
                         f"{rel} is marked _template: true — a template is not a record."))
        return None
    return doc


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

    # --- a writing workload needs the pre-schedule write gate ------------------
    #
    # Write-shaped tools reach canonical records. The 2026-09-13 sequencing
    # amendment makes an operational write admission and one verified manual
    # positive control the price of recurrence; a grant that permits such a
    # tool without naming that evidence is refused before any file is opened.
    write_tools = sorted(t for t in permitted if _write_shaped(t))
    pre = g("preconditions") or {}
    if write_tools and not pre.get("write_admission"):
        out.append(_fail(
            "GRANT_WRITE_TOOL_WITHOUT_ADMISSION",
            f"permitted_tools {write_tools} can mutate canonical records but the "
            f"grant carries no preconditions.write_admission. A write path is "
            f"admitted by a dated, host-observed receipt, never by listing the tool."))
    if write_tools and not pre.get("positive_control"):
        out.append(_fail(
            "GRANT_POSITIVE_CONTROL_MISSING",
            f"permitted_tools {write_tools} can mutate canonical records but the "
            f"grant carries no preconditions.positive_control. One manually "
            f"triggered, independently verified write precedes any recurring job."))

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


def check_preconditions(grant: dict, evidence_root: Path | None) -> list[str]:
    """Open the governed evidence the grant's preconditions name and cross-check
    it. Returns ALL refusals. Nothing here trusts a value that merely asserts a
    pass: every claim is matched against another record or a digest."""
    out: list[str] = []
    pre = grant.get("preconditions") or {}
    if not pre:
        return out
    if evidence_root is None or not evidence_root.is_dir():
        out.append(_fail("GRANT_EVIDENCE_ROOT_UNRESOLVED",
                         f"preconditions are declared but the evidence root "
                         f"{str(evidence_root)!r} is not a directory. Refusing rather "
                         f"than validating a grant against evidence it cannot open."))
        return out

    authority = grant.get("authority") or {}
    permitted = set((grant.get("envelope") or {}).get("permitted_tools") or [])
    target_agent = grant.get("target_agent_id")

    # ---- write admission ------------------------------------------------------
    wa = pre.get("write_admission") or {}
    adm = _load_evidence(evidence_root, wa.get("receipt", ""), "ADMISSION_RECEIPT", out) if wa else None
    expected_fields = set(wa.get("allowlisted_fields") or [])
    expected_tools = set(wa.get("admitted_tools") or [])
    if wa:
        stale = sorted(expected_tools - permitted)
        if stale:
            out.append(_fail(
                "GRANT_STALE_PHASE_A_ENVELOPE",
                f"preconditions.write_admission.admitted_tools {stale} are not in "
                f"envelope.permitted_tools. The grant still describes a read-only "
                f"workload beside a write admission; the scheduled workload must be "
                f"the admitted one, not a Phase-A leftover."))
        beyond = sorted(t for t in permitted if _write_shaped(t) and t not in expected_tools)
        if beyond:
            out.append(_fail(
                "GRANT_TOOLS_BEYOND_ADMISSION",
                f"envelope.permitted_tools {beyond} are write-shaped and not among the "
                f"admitted tools. Scheduling is not an occasion to widen the write path."))
    if adm is not None:
        miss = _missing(adm, _ADM_REQUIRED)
        obs = adm.get("observed") if isinstance(adm.get("observed"), dict) else {}
        miss += [f"observed.{k}" for k in _ADM_OBSERVED_REQUIRED if k not in obs or _is_placeholder(obs.get(k))]
        if miss:
            out.append(_fail("GRANT_ADMISSION_RECEIPT_INCOMPLETE",
                             f"admission receipt lacks {miss}."))
        if adm.get("kind") not in (None, "write-admission"):
            out.append(_fail("GRANT_ADMISSION_RECEIPT_INCOMPLETE",
                             f"admission receipt kind is {adm.get('kind')!r}, expected 'write-admission'."))
        if adm.get("admitted") is not True or str(adm.get("phase")) != str(wa.get("phase")):
            out.append(_fail(
                "GRANT_PHASE_NOT_ADMITTED",
                f"admission receipt says admitted={adm.get('admitted')!r} phase="
                f"{adm.get('phase')!r}; the grant requires an admitted phase "
                f"{wa.get('phase')!r}. The write allowlist may be approved and still "
                f"not admitted — approval is a decision, admission is an observation."))
        if (adm.get("task_id") != authority.get("task_id")
                or adm.get("decision_memory_page_id") != authority.get("decision_memory_page_id")
                or adm.get("worker_id") != target_agent):
            out.append(_fail(
                "GRANT_ADMISSION_AUTHORITY_MISMATCH",
                f"admission receipt binds {adm.get('task_id')}/{adm.get('decision_memory_page_id')}"
                f"/{adm.get('worker_id')}; the grant is {authority.get('task_id')}/"
                f"{authority.get('decision_memory_page_id')}/{target_agent}."))
        got_fields = set(adm.get("allowlisted_fields") or [])
        if got_fields != expected_fields:
            out.append(_fail(
                "GRANT_ADMISSION_ALLOWLIST_DRIFT",
                f"admission receipt allowlists {sorted(got_fields)}; the grant expects "
                f"exactly {sorted(expected_fields)}. Wider is a widening; narrower means "
                f"the workload was scheduled against a surface it does not have."))
        got_tools = set(adm.get("admitted_tools") or [])
        if got_tools != expected_tools:
            out.append(_fail(
                "GRANT_ADMISSION_TOOLS_DRIFT",
                f"admission receipt admits tools {sorted(got_tools)}; the grant expects "
                f"exactly {sorted(expected_tools)}."))
        caps = obs.get("connection_capabilities") if isinstance(obs.get("connection_capabilities"), dict) else {}
        for cap in ("insert_content", "comment", "user_info"):
            if caps.get(cap) is not False:
                out.append(_fail(
                    "GRANT_ADMISSION_CAPABILITY_WIDER_THAN_ALLOWLIST",
                    f"observed connection capability {cap!r} is {caps.get(cap)!r}, must be "
                    f"false. Insert/comment/user reach is outside the allowlist."))
        denial = obs.get("cross_agent_denial") if isinstance(obs.get("cross_agent_denial"), dict) else {}
        unproven = sorted(a for a, v in denial.items()
                          if _is_placeholder(v) or str(v).upper().startswith("UNKNOWN")
                          or str(v).upper().startswith("UNVERIFIED"))
        if not denial or unproven:
            out.append(_fail(
                "GRANT_ADMISSION_EXPOSURE_UNPROVEN",
                f"agent-local denial is not observed for {unproven or 'any agent'}. MCP "
                f"registration is Gateway-wide; an unproven denial is an exposure."))

    # ---- positive control -----------------------------------------------------
    pc = pre.get("positive_control") or {}
    if not pc:
        return out
    cohort_ids: set[str] = set()
    cohort_coord: dict[str, str] = {}
    cohort_rel = pc.get("cohort_packet", "")
    if not _safe_rel(cohort_rel):
        out.append(_fail("GRANT_EVIDENCE_PATH_UNSAFE", f"cohort_packet path {cohort_rel!r}."))
    else:
        cpath = evidence_root / cohort_rel
        if not cpath.is_file():
            out.append(_fail("GRANT_COHORT_PACKET_MISSING", f"{cohort_rel} not present under {evidence_root}."))
        elif _sha256_file(cpath) != pc.get("cohort_packet_sha256"):
            out.append(_fail(
                "GRANT_COHORT_DIGEST_MISMATCH",
                f"{cohort_rel} sha256 {_sha256_file(cpath)[:16]}… does not match the pinned "
                f"{str(pc.get('cohort_packet_sha256'))[:16]}…. The cohort the target must "
                f"belong to is not the cohort on disk."))
        else:
            try:
                cohort = json.loads(cpath.read_text())
                for r in cohort.get("records", []):
                    cohort_ids.add(r.get("page_id"))
                    cohort_coord[r.get("page_id")] = r.get("identity_coordinate")
            except (json.JSONDecodeError, AttributeError) as exc:
                out.append(_fail("GRANT_COHORT_PACKET_MISSING", f"{cohort_rel} unreadable: {exc}"))

    rec = _load_evidence(evidence_root, pc.get("receipt", ""), "POSITIVE_CONTROL", out)
    ver = _load_evidence(evidence_root, pc.get("verification", ""), "VERIFICATION", out)
    write: dict | None = None
    if rec is not None:
        miss = _missing(rec, _PC_REQUIRED)
        if miss:
            out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE",
                             f"positive-control receipt lacks {miss}. TASK-323 criterion 6 "
                             f"names every one of these; a receipt missing one is incomplete."))
        if "manual_run_id" in miss:
            out.append(_fail("GRANT_POSITIVE_CONTROL_NO_RUN_ID",
                             "manual_run_id is absent or a placeholder. The run the runtime "
                             "exposed is the only thing that ties this receipt to an execution."))
        if rec.get("kind") not in (None, "positive-control"):
            out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE",
                             f"receipt kind is {rec.get('kind')!r}, expected 'positive-control'."))
        if str(rec.get("trigger", "")).lower() != "manual":
            out.append(_fail("GRANT_POSITIVE_CONTROL_NOT_MANUAL",
                             f"trigger is {rec.get('trigger')!r}; the positive control is the "
                             f"one manually triggered run, not a scheduled one."))
        if rec.get("counts_toward_scheduled_runs") is not False:
            out.append(_fail("GRANT_POSITIVE_CONTROL_COUNTED_AS_SCHEDULED",
                             "counts_toward_scheduled_runs must be false: the manual write "
                             "does not count toward the five scheduled proof runs."))
        if (rec.get("task_id") != authority.get("task_id")
                or rec.get("decision_memory_page_id") != authority.get("decision_memory_page_id")
                or rec.get("worker_id") != target_agent):
            out.append(_fail(
                "GRANT_POSITIVE_CONTROL_AUTHORITY_MISMATCH",
                f"receipt binds {rec.get('task_id')}/{rec.get('decision_memory_page_id')}/"
                f"{rec.get('worker_id')}; the grant is {authority.get('task_id')}/"
                f"{authority.get('decision_memory_page_id')}/{target_agent}."))
        if str(rec.get("terminal_state", "")).upper() != "VERIFIED SUCCESS":
            out.append(_fail("GRANT_POSITIVE_CONTROL_NOT_VERIFIED_SUCCESS",
                             f"terminal_state is {rec.get('terminal_state')!r}. Any other "
                             f"state is a STOP; the schedule stays withheld."))
        writes = rec.get("writes") if isinstance(rec.get("writes"), list) else []
        if len(writes) != 1:
            out.append(_fail("GRANT_POSITIVE_CONTROL_WRITE_COUNT",
                             f"receipt declares {len(writes)} write(s); exactly one bounded "
                             f"allowlisted write is the positive control."))
        else:
            write = writes[0] if isinstance(writes[0], dict) else {}
            wmiss = _missing(write, _PC_WRITE_REQUIRED)
            # `prior` may legitimately be empty (an empty Evidence URL) — only absence counts.
            wmiss = [k for k in wmiss if not (k == "prior" and "prior" in write and write["prior"] == "")]
            ev = write.get("evidence") if isinstance(write.get("evidence"), dict) else {}
            wmiss += [f"evidence.{k}" for k in _PC_EVIDENCE_REQUIRED if _is_placeholder(ev.get(k))]
            if wmiss:
                out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE",
                                 f"the declared write lacks {wmiss}."))
            if expected_fields and write.get("field") not in expected_fields:
                out.append(_fail(
                    "GRANT_POSITIVE_CONTROL_FIELD_NOT_ALLOWLISTED",
                    f"the write targets field {write.get('field')!r}, which is not in the "
                    f"admitted allowlist {sorted(expected_fields)}. A protected-field write "
                    f"is the failure the gate exists to catch, not a positive control."))
            tgt = rec.get("target") if isinstance(rec.get("target"), dict) else {}
            if cohort_ids and (write.get("page_id") not in cohort_ids
                               or tgt.get("page_id") != write.get("page_id")):
                out.append(_fail(
                    "GRANT_POSITIVE_CONTROL_TARGET_OUTSIDE_COHORT",
                    f"target page {tgt.get('page_id')!r} / written page {write.get('page_id')!r} "
                    f"is not in the pinned cohort packet. The target is chosen from the "
                    f"admitted cohort, never from the ledger at large."))
            elif cohort_ids and cohort_coord.get(write.get("page_id")) != grant.get("identity_coordinate"):
                out.append(_fail(
                    "GRANT_POSITIVE_CONTROL_TARGET_OUTSIDE_COHORT",
                    f"target page carries identity coordinate "
                    f"{cohort_coord.get(write.get('page_id'))!r}, grant is "
                    f"{grant.get('identity_coordinate')!r}."))
            if str(tgt.get("task_id")) != str(write.get("task_id")):
                out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE",
                                 "target.task_id and the declared write's task_id disagree."))
        sel = rec.get("selection_record") if isinstance(rec.get("selection_record"), dict) else {}
        if _missing(sel, ("page_id", "section", "selected_by")):
            out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE",
                             "selection_record must name the canonical page, the dated section "
                             "and who selected the target — a deliberately selected task is one "
                             "selected on the record, not in a payload."))
        wr_rel = rec.get("worker_receipt_path")
        if isinstance(wr_rel, str) and _safe_rel(wr_rel):
            wr = evidence_root / wr_rel
            if not wr.is_file():
                out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE",
                                 f"worker receipt {wr_rel} is not present; the worker's own "
                                 f"plain-text receipt is part of the record."))
            elif _sha256_file(wr) != rec.get("worker_receipt_sha256"):
                out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE",
                                 f"worker receipt {wr_rel} sha256 does not match "
                                 f"worker_receipt_sha256 — the transcript and the record differ."))
        elif wr_rel is not None and not _is_placeholder(wr_rel):
            out.append(_fail("GRANT_EVIDENCE_PATH_UNSAFE", f"worker_receipt_path {wr_rel!r}."))

    if ver is not None:
        vmiss = _missing(ver, _VER_REQUIRED)
        if vmiss:
            out.append(_fail("GRANT_VERIFICATION_INCOMPLETE", f"verification lacks {vmiss}."))
        if verification_digest(ver) != ver.get("result_digest"):
            out.append(_fail(
                "GRANT_VERIFICATION_DIGEST_MISMATCH",
                "the verification's result_digest does not match its content. The file "
                "was edited after the verifier wrote it, or was not written by the verifier."))
        inputs = ver.get("inputs") if isinstance(ver.get("inputs"), dict) else {}
        pc_rel = pc.get("receipt", "")
        if rec is not None and _safe_rel(pc_rel):
            if inputs.get("receipt_sha256") != _sha256_file(evidence_root / pc_rel):
                out.append(_fail(
                    "GRANT_VERIFICATION_RECEIPT_UNBOUND",
                    "verification.inputs.receipt_sha256 is not the digest of the positive-"
                    "control receipt on disk. The verification proves some receipt, not "
                    "this one."))
        if str(ver.get("result", "")).upper() != "VERIFIED":
            out.append(_fail("GRANT_VERIFICATION_REFUSED",
                             f"verifier result is {ver.get('result')!r}. A refused or absent "
                             f"verification is a STOP."))
        pfc = ver.get("protected_field_changes")
        if pfc != 0:
            out.append(_fail("GRANT_PROTECTED_FIELD_DIFF_NONZERO",
                             f"protected_field_changes = {pfc!r}; required 0."))
        dup = ver.get("duplicate_shadow_tasks")
        if dup != 0:
            out.append(_fail("GRANT_DUPLICATE_SHADOW_TASKS_NONZERO",
                             f"duplicate_shadow_tasks = {dup!r}; required 0. UNKNOWN is not 0 — "
                             f"a ledger comparison that did not run cannot vouch for the ledger."))
        unx = ver.get("unexplained_changes")
        if unx != 0:
            out.append(_fail("GRANT_UNEXPLAINED_CHANGES_NONZERO",
                             f"unexplained_changes = {unx!r}; required 0."))
        declared = ver.get("declared_writes") if isinstance(ver.get("declared_writes"), list) else []
        if write is not None:
            match = [d for d in declared if isinstance(d, dict)
                     and d.get("page_id") == write.get("page_id")
                     and d.get("field") == write.get("field")
                     and _canon(d.get("prior")) == _canon(write.get("prior"))
                     and _canon(d.get("new")) == _canon(write.get("new"))
                     and d.get("observed") is True]
            if len(match) != 1 or len(declared) != 1:
                out.append(_fail(
                    "GRANT_INTENDED_MUTATION_MISMATCH",
                    f"the verifier observed {len(declared)} declared write(s), of which "
                    f"{len(match)} match the receipt's write (page, field, prior, new, "
                    f"observed=true). The intended mutation is not proven to be the one "
                    f"that happened."))

    # ---- ordering: admitted, then run, then verified ---------------------------
    t_adm = _ts((adm or {}).get("admitted_at")) if adm else None
    t_start = _ts((rec or {}).get("run_started_at")) if rec else None
    t_end = _ts((rec or {}).get("run_completed_at")) if rec else None
    t_ver = _ts((ver or {}).get("verified_at")) if ver else None
    if adm and rec and t_adm and t_start and t_start < t_adm:
        out.append(_fail("GRANT_POSITIVE_CONTROL_BEFORE_ADMISSION",
                         f"the positive-control run started {t_start.isoformat()} before the "
                         f"write path was admitted {t_adm.isoformat()}."))
    if rec and t_start and t_end and t_end < t_start:
        out.append(_fail("GRANT_POSITIVE_CONTROL_INCOMPLETE", "run_completed_at precedes run_started_at."))
    if rec and ver and t_end and t_ver and t_ver < t_end:
        out.append(_fail("GRANT_VERIFICATION_INCOMPLETE",
                         f"verified_at {t_ver.isoformat()} precedes the run's completion "
                         f"{t_end.isoformat()}; a verification cannot precede what it verifies."))
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
    ap.add_argument("--evidence-root", default=None,
                    help="directory the grant's preconditions evidence paths resolve under "
                         "(default: preconditions.evidence_root relative to the grant file)")
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

    evidence_root: Path | None = None
    if isinstance(grant.get("preconditions"), dict):
        if args.evidence_root:
            evidence_root = Path(args.evidence_root)
        else:
            rel = grant["preconditions"].get("evidence_root") or "."
            evidence_root = (Path(args.grant).resolve().parent / rel).resolve()

    violations = (check_schema(grant, schema) + check_policy(grant, profile)
                  + check_preconditions(grant, evidence_root))

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
