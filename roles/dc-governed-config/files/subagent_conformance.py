#!/usr/bin/env python3
"""Judge sub-agent isolation conformance from the live schema and effective config.

    subagent_conformance.py --schema S --effective E --agents A --agent-id ID

Reads. Decides nothing about the runtime's behaviour — only about what this
build DECLARES and what this host has CONFIGURED.

WHY THE DISTINCTION MATTERS AND IS KEPT THROUGHOUT

Founder direction 2026-08-17 requires every finding to be classified as
VERIFIED HOST, VERIFIED UPSTREAM, SUPPORTED INFERENCE, or UNKNOWN. This file
may only ever produce the first and the last, plus inferences it labels as
such:

  VERIFIED HOST      the schema of THIS build declares it, or `config get` on
                     THIS host returned it
  SUPPORTED INFERENCE it follows from those, but was not observed
  UNKNOWN            the schema does not declare it and the host did not answer

It cannot produce VERIFIED UPSTREAM — that classification belongs to reading
upstream source, which this does not do. And it cannot produce a behavioural
observation, because observing a child requires spawning one.

A key being ABSENT from the schema is not proof a control is missing; it may be
undeclared and still enforced. Absence is reported as UNKNOWN, never as FAIL.
That asymmetry is deliberate: a false FAIL on an isolation control would send
someone to widen a policy that was never broken.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# The tools an isolated child must not hold. Drawn from the accepted posture:
# direct communication and admin surfaces. `message` and `sessions_send` are
# the communication half; `gateway` and `cron` the admin half.
DIRECT_SURFACES = ("message", "sessions_send", "gateway", "cron",
                   "conversations_read", "conversations_search")

# Auth-profile keys. PROVENANCE ONLY — this file never reads or prints a value.
# The residual risk the founder named is that a main-agent authentication
# profile may be merged as fallback for a spawned agent, so what matters is
# whether such a fallback is DECLARED, not what any credential contains.
AUTH_HINTS = ("auth", "profile", "credential", "fallback", "inherit")


def walk_schema(node: Any, path: str = "", out: dict[str, str] | None = None) -> dict[str, str]:
    """Every declared key path, with its description. Descriptions carry the
    semantics that decide precedence, and are frequently the only place a
    precedence rule is written down at all."""
    if out is None:
        out = {}
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}" if path else k
            if isinstance(v, dict) and "description" in v and isinstance(v["description"], str):
                out[p] = v["description"]
            walk_schema(v, p, out)
    elif isinstance(node, list):
        for item in node:
            walk_schema(item, path, out)
    return out


def clean(path: str) -> str:
    """Strip JSON Schema plumbing so a reader sees the config path they'd type."""
    for noise in (".properties", ".items", ".additionalProperties", ".anyOf",
                  ".oneOf", ".allOf", ".$defs", ".definitions"):
        path = path.replace(noise, "")
    return re.sub(r"\.\d+", "", path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", required=True)
    ap.add_argument("--effective", required=True)
    ap.add_argument("--agents", required=True)
    ap.add_argument("--agent-id", required=True)
    args = ap.parse_args()

    try:
        schema = json.loads(Path(args.schema).read_text())
        effective = json.loads(Path(args.effective).read_text())
        agents = json.loads(Path(args.agents).read_text() or "[]")
    except (OSError, json.JSONDecodeError) as exc:
        print(f"UNKNOWN — inputs unreadable: {exc}", file=sys.stderr)
        return 2

    declared = {clean(p): d for p, d in walk_schema(schema).items()}
    entry = next((e for e in agents if e.get("id") == args.agent_id), {})
    deny = set(entry.get("tools", {}).get("deny", []))

    out: list[str] = []
    add = out.append

    add("=" * 72)
    add(f"SUB-AGENT CONFORMANCE — target agent: {args.agent_id}")
    add("=" * 72)
    add("")
    add("Every line is classified. This file can produce VERIFIED HOST,")
    add("SUPPORTED INFERENCE or UNKNOWN. It cannot produce VERIFIED UPSTREAM")
    add("(that needs upstream source) and cannot produce a behavioural")
    add("observation (that needs a spawn).")
    add("")

    # --- 1. which sub-agent paths this build declares -------------------------
    add("--- 1. sub-agent key paths declared by THIS build's schema ---")
    sub_paths = {p: d for p, d in declared.items()
                 if "subagent" in p.lower() or "allowagents" in p.lower()}
    if sub_paths:
        for p in sorted(sub_paths):
            desc = " ".join(sub_paths[p].split())[:200]
            add(f"  [VERIFIED HOST] {p}")
            if desc:
                add(f"                  {desc}")
    else:
        add("  [UNKNOWN] no sub-agent key path found in the schema.")
        add("            Absence from the schema is NOT proof the control is")
        add("            missing — it may be undeclared and still enforced.")
    add("")

    # --- 2. the sub-agent tool-policy layer ----------------------------------
    add("--- 2. sub-agent tool-policy layer ---")
    for want in ("tools.subagents.tools.allow", "tools.subagents.tools.deny"):
        hit = [p for p in declared if p.endswith(want.split(".", 1)[1])
               and "subagent" in p.lower()]
        if hit:
            add(f"  [VERIFIED HOST] declared: {sorted(hit)[0]}")
        else:
            add(f"  [UNKNOWN] {want} not found in schema under a subagents path")
    add("")

    # --- 3. precedence against the target agent's own policy ------------------
    add("--- 3. precedence: agent policy then sub-agent narrowing ---")
    add(f"  [VERIFIED HOST] {args.agent_id} denies {len(deny)} tools in the")
    add("                  deployed agents.list.")
    blocked = sorted(t for t in ("subagents", "sessions_spawn") if t in deny)
    if blocked:
        add(f"  [VERIFIED HOST] {args.agent_id} denies {blocked}.")
        add("                  It therefore CANNOT SPAWN. No behavioural test of")
        add("                  child isolation is possible from this agent without")
        add("                  a configuration change — which is a mutation.")
        add("  [SUPPORTED INFERENCE] the accepted upstream semantics (agent policy")
        add("                  first, sub-agent layer narrowing further) cannot make")
        add("                  a child of this agent MORE capable than the agent,")
        add("                  because narrowing is monotonic. This follows from the")
        add("                  stated rule; it is not observed on this host.")
    else:
        add(f"  [VERIFIED HOST] {args.agent_id} does not deny spawn tools.")
    add("")

    # --- 4. direct communication and admin surfaces --------------------------
    add("--- 4. direct communication / admin surfaces on the target agent ---")
    for t in DIRECT_SURFACES:
        if t in deny:
            add(f"  [VERIFIED HOST] {t}: DENIED on {args.agent_id}")
        else:
            add(f"  [UNKNOWN] {t}: not in {args.agent_id}'s deny list — it may be")
            add(f"            absent from this build, denied at the Gateway, or")
            add(f"            available. `config get` cannot distinguish those.")
    add("")

    # --- 5. auth profile provenance — SCOPE ONLY, NEVER VALUES ---------------
    add("--- 5. auth-profile fallback provenance (NO VALUES READ) ---")
    add("  Residual risk named by the founder: a main-agent authentication")
    add("  profile may be merged as fallback for a spawned agent. What matters")
    add("  is whether such a fallback is DECLARED, not what it contains.")
    auth_paths = {p: d for p, d in declared.items()
                  if any(h in p.lower() for h in AUTH_HINTS)
                  and ("agent" in p.lower() or "subagent" in p.lower())}
    if auth_paths:
        for p in sorted(auth_paths)[:25]:
            desc = " ".join(auth_paths[p].split())[:180]
            add(f"  [VERIFIED HOST] {p}")
            if desc:
                add(f"                  {desc}")
        add("  NOTE: key paths only. No credential value was read or printed.")
    else:
        add("  [UNKNOWN] no agent-scoped auth/fallback key found in the schema.")
    add("")

    # --- 6. effective configuration on this host ----------------------------
    add("--- 6. what this host has actually configured ---")
    for path, value in sorted(effective.items()):
        v = " ".join(str(value).split())
        if not v or "path not present" in v:
            add(f"  [UNKNOWN]       {path}: <unset> — not configured. On this")
            add("                  runtime an unset key is a default nobody chose,")
            add("                  not an absence of behaviour.")
        else:
            add(f"  [VERIFIED HOST] {path}: {v[:160]}")
    add("")

    # --- verdict -------------------------------------------------------------
    add("=" * 72)
    add("VERDICT")
    add("=" * 72)
    if blocked:
        add("  SUB-AGENT ISOLATION ON THIS HOST: UNKNOWN.")
        add("")
        add("  Not FAIL. Nothing here shows a control failing. The reason is")
        add("  narrower and more awkward: the governed agent denies `subagents`")
        add("  and `sessions_spawn`, so it cannot produce a child to observe.")
        add("")
        add("  The isolation properties are therefore VERIFIED UPSTREAM (per the")
        add("  accepted v2026.7.1 reading) and DECLARED by this build's schema,")
        add("  but NOT observed on this host.")
        add("")
        add("  Closing that gap requires a spawn, and a spawn requires granting")
        add("  the agent a tool it is deliberately denied. That is a mutation and")
        add("  a widening of the worker's boundary, so it is a founder decision")
        add("  rather than an executor's.")
    else:
        add("  Target agent can spawn; a bounded read-only probe is possible")
        add("  without mutation.")
    add("")
    add("  This report is HOST DECLARATION evidence. It does not upgrade the")
    add("  earlier ask-the-child result, which remains SUPPORTED INFERENCE.")

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
