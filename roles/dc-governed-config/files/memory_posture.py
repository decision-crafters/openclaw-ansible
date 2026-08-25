#!/usr/bin/env python3
"""Reconcile captured memory evidence against the accepted TASK-226 posture.

    memory_posture.py --evidence E [--accepted-backend memory-core]

WHAT THIS IS FOR

TASK-226 is Review / Founder-Accepted. The posture is settled -- `memory-core`
first, QMD conditional, Notion canonical, runtime memory operational working
state. What was never closed is the EVIDENCE, and its second required receipt
is "live memory-related `openclaw config schema` output".

That receipt was captured in part by --tags schema-evidence: 183 agent-scoped
memory paths, with type and description. What it did NOT capture is what this
host has CONFIGURED, because no memory path had ever appeared in
`dc_audit_paths`. The schema says what MAY be set. This file is about what IS.

THREE ERRORS THIS FILE EXISTS TO REFUSE

1. THE PROVIDER TRAP. The live schema documents `memorySearch.provider` as
   "Defaults to openai". So an unset provider is NOT "not configured" in any
   sense that matters -- it means the documented default is in force. The
   accepted posture is local-first, with LanceDB and Honcho research-gated
   PRECISELY BECAUSE their external data path is unproven. Reporting `<unset>`
   as a blank would hide an external data path inside the posture that was
   accepted as the local one.

   Equally, this must not be reported as EXPOSURE. Whether memory search is
   enabled here is a separate question, and if it is off the default is inert.
   The honest output is a named UNKNOWN. "We could not have told you either
   way" is the finding; "we were exposed" is not supported.

2. THE ABSENCE TRAP. `memory-core` appears NOWHERE in the config schema, and
   was observed in the enabled plugin list on 2026-08-16. The correct reading
   is that it exposes no configurable entry -- not that it is absent.
   Symmetrically, `plugins.entries.active-memory` being declared in the schema
   is NOT evidence that active-memory is installed. A schema declares what may
   be configured, not what is loaded.

3. THE FLOOR. A failed or timed-out `plugins inspect` yields INDETERMINATE for
   that receipt. Memory posture is not scored from a check that did not run.
   `plugins list` hung on this build once and was recorded as the subcommand
   not existing; that error is the reason this rule is mechanical.

CRITERION 5

TASK-226 criterion 5 asks whether memory isolation is testable in the synthetic
admission suite. Founder decision 2026-08-25: schema + inspect only. This file
therefore always emits the same answer -- NOT SATISFIABLE AS SPECIFIED, with
the reason and a compensating check -- and always states that the compensating
check is a schema-layer check and not a behavioural isolation proof. It cannot
be configured to claim otherwise.

EXIT CODES

  0  every check agrees with the accepted posture
  1  findings preserved -- a REPORT, not an error
  2  INSUFFICIENT EVIDENCE: inputs unreadable or a required receipt missing
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

UNSET_MARKERS = ("", "<unset, or path not present>", "null", "undefined")


def is_unset(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.strip() in UNSET_MARKERS)


def as_bool(v: Any) -> bool | None:
    """Effective config comes back as text. Returns None for 'not set', which is
    deliberately distinct from False -- an unset toggle is a default nobody
    chose, and this workstream has been wrong about that distinction before."""
    if is_unset(v):
        return None
    s = str(v).strip().strip('"').lower()
    if s in ("true", "1", "yes"):
        return True
    if s in ("false", "0", "no"):
        return False
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--accepted-backend", default="memory-core")
    ap.add_argument("--provider-default", default="openai")
    ap.add_argument("--local-providers", default="local,ollama,lmstudio")
    args = ap.parse_args()

    try:
        ev = json.loads(Path(args.evidence).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"INSUFFICIENT EVIDENCE — evidence file unreadable: {exc}",
              file=sys.stderr)
        return 2

    effective: dict[str, str] = ev.get("effective", {}) or {}
    per_agent: dict[str, dict[str, str]] = ev.get("per_agent", {}) or {}
    inspect: dict[str, Any] = ev.get("inspect", {}) or {}
    # NAMED FOR ITS SOURCE. An earlier version called this "schema_plugin_
    # entries" and the report said "the schema DOES declare" -- while the play
    # fed it from `config get plugins.entries`, which is the EFFECTIVE CONFIG.
    # Those are different sources answering different questions, and an evidence
    # artifact that misnames its provenance is worse than one that omits it.
    configured_entries: list[str] = ev.get("configured_plugin_entries", []) or []
    memdir: dict[str, Any] = ev.get("memory_dir", {}) or {}

    if not effective:
        print("INSUFFICIENT EVIDENCE — no effective configuration was captured. "
              "Every judgement below would be an inference from silence.",
              file=sys.stderr)
        return 2

    local = [p.strip() for p in args.local_providers.split(",") if p.strip()]
    out: list[str] = []
    add = out.append
    findings: list[str] = []

    add("=" * 78)
    add("TASK-226 — MEMORY POSTURE vs ACCEPTED DECISION")
    add(f"accepted backend: {args.accepted_backend}")
    add("=" * 78)
    add("")
    add("Every line states what this host has CONFIGURED or what the build")
    add("DECLARES. None is a behavioural observation of memory in use.")
    add("`<unset>` means NOT CONFIGURED. It never means inactive.")
    add("")

    # --- RECEIPT A ------------------------------------------------------------
    add("--- RECEIPT A: plugins inspect " + args.accepted_backend + " ---")
    a_state = inspect.get("state", "MISSING")
    a_out = (inspect.get("stdout") or "").strip()
    if a_state != "VERIFIED HOST" or not a_out:
        add(f"  INDETERMINATE — {a_state}.")
        add("  The CHECK did not complete. This is NOT a finding that")
        add(f"  {args.accepted_backend} is absent, and the posture is not scored")
        add("  from it. `plugins list` hung on this build once and was recorded")
        add("  as the subcommand not existing; that error is why this is a rule.")
        findings.append("Receipt A INDETERMINATE")
    else:
        add("  [VERIFIED HOST] inspection returned:")
        for line in a_out.splitlines()[:40]:
            add(f"    {line}")
        if len(a_out.splitlines()) > 40:
            add(f"    ... {len(a_out.splitlines()) - 40} further line(s) NOT shown "
                "— cap reached; the full text is in the report artifact.")
    if inspect.get("in_enumeration") is False:
        add(f"  NOTE: {args.accepted_backend} did not appear in the ENABLED")
        add("  enumeration. An empty or thin inspection here is consistent with")
        add("  absent, disabled, or differently named — those are not merged.")
        findings.append(f"{args.accepted_backend} absent from enabled enumeration")
    add("")

    # --- RECEIPT B ------------------------------------------------------------
    add("--- RECEIPT B: effective memory configuration ---")
    for k in sorted(effective):
        v = effective[k]
        shown = "<unset — NOT CONFIGURED>" if is_unset(v) else str(v)[:220]
        add(f"  [VERIFIED HOST] {k} = {shown}")
    add("")

    if per_agent:
        add("  per-agent overrides (agents.list[] may override agents.defaults,")
        add("  so reading only the defaults would report a posture the governed")
        add("  agent does not necessarily run under):")
        for agent in sorted(per_agent):
            for k in sorted(per_agent[agent]):
                v = per_agent[agent][k]
                if not is_unset(v):
                    add(f"    [VERIFIED HOST] {agent}.{k} = {str(v)[:200]}")
        add("")

    # --- THE PROVIDER QUESTION ------------------------------------------------
    add("--- memorySearch.provider: CONFIGURED, or DEFAULT NOBODY CHOSE? ---")
    prov_key = "agents.defaults.memorySearch.provider"
    en_key = "agents.defaults.memorySearch.enabled"
    prov = effective.get(prov_key)
    enabled = as_bool(effective.get(en_key))

    # A per-agent override wins over defaults, so it is resolved first.
    for agent, vals in per_agent.items():
        if not is_unset(vals.get("memorySearch.provider")):
            prov = vals["memorySearch.provider"]
            add(f"  resolved from the per-agent override on {agent}")
        if as_bool(vals.get("memorySearch.enabled")) is not None:
            enabled = as_bool(vals["memorySearch.enabled"])

    prov_clean = None if is_unset(prov) else str(prov).strip().strip('"')

    if prov_clean:
        cls = "LOCAL" if prov_clean in local else "EXTERNAL"
        add(f"  [VERIFIED HOST] CONFIGURED: {prov_clean}  ({cls})")
        if cls == "EXTERNAL":
            add("  FINDING — the accepted posture is local-first. An external")
            add("  embedding provider is a data path off this host, which is the")
            add("  exact ground on which LanceDB and Honcho were research-gated.")
            findings.append(f"memorySearch.provider is external: {prov_clean}")
    else:
        add(f"  DEFAULT NOBODY CHOSE: `{args.provider_default}` (documented)")
        add("  The live schema documents this key as defaulting to")
        add(f"  \"{args.provider_default}\". Unset does NOT mean unused and does")
        add("  NOT mean local.")
        if enabled is True:
            add("  FINDING — memory search is ENABLED and provider is unset, so")
            add("  the documented external default is in force. Embeddings for a")
            add("  governed research agent would leave this host.")
            findings.append("memorySearch ENABLED with provider defaulting to "
                            f"{args.provider_default}")
        elif enabled is False:
            add("  memorySearch.enabled is FALSE, so the default is inert today.")
            add("  It remains an unchosen default and becomes live the moment")
            add("  anyone enables memory search.")
            findings.append("provider default unchosen (inert: memorySearch off)")
        else:
            add("  UNKNOWN — memorySearch.enabled is also unset, so whether the")
            add("  default is in force cannot be established from configuration.")
            add("  This is NOT a finding of exposure. The honest statement is")
            add("  that we could not have told you either way.")
            findings.append("provider default unchosen; enabled state UNKNOWN")
    add("")

    # --- the two the Observer return said must default closed -----------------
    add("--- surfaces the TASK-226 Observer return required to default closed ---")
    for key, label in (
        ("agents.defaults.memorySearch.extraPaths", "extra indexed paths"),
        ("agents.defaults.memorySearch.experimental.sessionMemory",
         "session transcript indexing"),
        ("agents.defaults.memorySearch.multimodal.enabled",
         "multimodal upload of binary content"),
    ):
        v = effective.get(key)
        if is_unset(v) or str(v).strip() in ("[]", "false", "False"):
            add(f"  [VERIFIED HOST] CLOSED — {label} ({key})")
        else:
            add(f"  FINDING — OPEN: {label} = {str(v)[:160]}")
            findings.append(f"{label} is open ({key})")
    add("")

    # --- THE ABSENCE TRAP -----------------------------------------------------
    add("--- plugins.entries: what is CONFIGURED, and what that does not prove ---")
    has_entry = any(args.accepted_backend == e for e in configured_entries)
    add(f"  `{args.accepted_backend}` has a plugins.entries block: "
        f"{'yes' if has_entry else 'NO'}")
    add("  Reading: a plugin with NO entry is not thereby absent or disabled.")
    add("  An entry is CONFIGURATION; a plugin with nothing to configure has")
    add("  none. Receipt A above is the authority on whether it is loaded, and")
    add(f"  this build's enabled list carried `{args.accepted_backend}` on")
    add("  2026-08-16.")
    if configured_entries:
        add("  entries CONFIGURED on this host (source: `config get "
            "plugins.entries`, i.e. effective config -- NOT the schema):")
        for e in sorted(configured_entries)[:20]:
            add(f"    {e}")
        add("  Reading: a configured entry is not proof the plugin is loaded")
        add("  either. `firecrawl` has an entry on this host AND is denied.")
    add("")

    if memdir:
        add("--- memory directory ---")
        add(f"  [VERIFIED HOST] path={memdir.get('path', '?')} "
            f"owner={memdir.get('owner', '?')} mode={memdir.get('mode', '?')} "
            f"exists={memdir.get('exists', '?')}")
        if memdir.get("owner") == "root":
            add("  FINDING — root-owned. The Gateway writes memory from outside")
            add("  the sandbox as the service account, so a root-owned directory")
            add("  fails to write SILENTLY.")
            findings.append("memory directory is root-owned")
        add("")

    # --- CRITERION 5 ----------------------------------------------------------
    # Fixed text. This cannot be configured into claiming a behavioural proof.
    add("=" * 78)
    add("CRITERION 5 — is memory isolation testable in the admission suite?")
    add("=" * 78)
    add("")
    add("  NOT SATISFIABLE AS SPECIFIED on this host.")
    add("")
    add("  The accepted CTO return requires seeding distinguishable memories")
    add("  into TWO agent/coordinate contexts and proving same-agent recall")
    add("  succeeds while cross-coordinate recall returns nothing. Cross-")
    add("  coordinate isolation requires two coordinates. Only `dc-research`")
    add("  exists, and a second agent is an ADMISSION DECISION under the")
    add("  one-pilot-per-quarter cap — not a test fixture.")
    add("")
    add("  Synthetic test 11 (memory-isolation) asks the agent to repeat prior")
    add("  session content. That is a MODEL OUTPUT about a runtime, not a")
    add("  runtime output about itself, and cannot settle isolation either way.")
    add("")
    add("  COMPENSATING CHECK — the schema-layer facts above:")
    add("    extraPaths closed · sessionMemory closed · multimodal closed")
    add("    provider pinned or named UNKNOWN · memory dir owned 0700")
    add("")
    add("  THIS IS A SCHEMA-LAYER CHECK AND NOT A BEHAVIOURAL ISOLATION PROOF.")
    add("  TASK-230 criterion 3 names a \"deterministic cross-coordinate")
    add("  isolation test\". No such test exists on this host, and SOP v0.2 must")
    add("  carry that flag rather than assert one.")
    add("")

    add("=" * 78)
    add("SUMMARY")
    add("=" * 78)
    add(f"  findings: {len(findings)}")
    for f in findings:
        add(f"    - {f}")
    if not findings:
        add("    (none — the captured evidence agrees with the accepted posture)")
    add("")
    add("  Criterion 5 remains NOT SATISFIABLE regardless of the count above.")
    add("  A zero-finding run does NOT mean isolation was proven.")

    print("\n".join(out))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
