#!/usr/bin/env python3
"""The merge contract for roles/dc-governed-config, proven rather than assumed.

The role applies its controls with Ansible's `combine(recursive=True)`, which is
a one-line expression whose behaviour is easy to state and easy to get wrong.
Two properties have to hold at once and they pull in opposite directions:

  1. Governance wins. A permissive value written by `openclaw onboard` must be
     replaced, or the role does nothing on precisely the hosts it exists for.
  2. Everything else survives. Onboarding writes channel tokens, model choices
     and agent entries that this role has no business touching.

This file reimplements the merge and asserts both. It found a real defect on
first run: `tools.allow` survived, and since OpenClaw treats a non-empty allow
list as blocking everything outside it, the effective policy would have been
partly ours and partly onboarding's. The fix was to clear `allow` explicitly,
and the test below now pins that.

Run: python3 tests/dc_merge_contract.py
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

ROLE = Path(__file__).resolve().parents[1] / "roles" / "dc-governed-config"


def combine_recursive(base: dict, over: dict) -> dict:
    """Mirror of Ansible's `combine(recursive=True)`.

    Dicts merge key by key; every other type is replaced wholesale. That second
    half is why the deny list and the allow list behave as they do here: both
    are lists, so the overlay's value wins outright rather than being unioned
    with whatever was there.
    """
    out = copy.deepcopy(base)
    for key, value in over.items():
        if key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = combine_recursive(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_defaults() -> dict[str, Any]:
    """Read the role defaults so the test tracks the role, not a copy of it.

    Deliberately fails rather than falling back to constants. A fallback would
    let this file pass while asserting values the role no longer holds — the
    test would be green and meaningless, which is worse than absent. Every
    control below is read from the role; none is hardcoded here.
    """
    try:
        import yaml  # noqa: PLC0415 - import guarded so the failure can be explained
    except ImportError:  # pragma: no cover - environment defect, not logic
        raise SystemExit(
            "PyYAML is required. Without it this test would silently assert its "
            "own constants instead of the role's defaults, and would pass even "
            "if the role were changed to something permissive."
        ) from None

    path = ROLE / "defaults" / "main.yml"
    defaults = yaml.safe_load(path.read_text()) or {}

    required = [
        "dc_tools_deny", "dc_tools_allow", "dc_sandbox_mode",
        "dc_sandbox_workspace_access", "dc_gateway_bind",
        "dc_sandbox_scope", "dc_tools_exec_mode", "dc_sandbox_docker_network",
    ]
    missing = [key for key in required if key not in defaults]
    if missing:
        raise SystemExit(
            f"{path} is missing {missing}. A control absent from defaults is "
            "not a control with a safe default — it is one this test can no "
            "longer prove."
        )
    return defaults


DEFAULTS = load_defaults()

DENY = DEFAULTS["dc_tools_deny"]
ALLOW = DEFAULTS["dc_tools_allow"]
SANDBOX_MODE = DEFAULTS["dc_sandbox_mode"]
WORKSPACE = DEFAULTS["dc_sandbox_workspace_access"]
BIND = DEFAULTS["dc_gateway_bind"]
SCOPE = DEFAULTS["dc_sandbox_scope"]
EXEC_MODE = DEFAULTS["dc_tools_exec_mode"]
DOCKER_NETWORK = DEFAULTS["dc_sandbox_docker_network"]

# Deliberately the worst realistic starting point: everything this role cares
# about is set to the permissive value. A merge tested against an already-safe
# config would pass without proving anything.
ONBOARDED: dict[str, Any] = {
    "agents": {
        "defaults": {
            "sandbox": {"mode": "off", "workspaceAccess": "rw"},
            "model": "anthropic/claude-sonnet-4",
        },
        "entries": [{"id": "main", "workspace": "~/work"}],
    },
    "tools": {"allow": ["read", "exec", "write"], "elevated": {"enabled": True}},
    "gateway": {"bind": "0.0.0.0", "port": 18789},
    "channels": {"telegram": {"token": "KEEP-ME"}},
    "session": {"historyLimit": 50},
}

OVERLAY: dict[str, Any] = {
    "agents": {"defaults": {"sandbox": {
        "mode": SANDBOX_MODE, "scope": SCOPE, "workspaceAccess": WORKSPACE,
        "docker": {"network": DOCKER_NETWORK}}}},
    "tools": {"allow": ALLOW, "deny": DENY, "exec": {"mode": EXEC_MODE},
              "elevated": {"enabled": False}},
    "gateway": {"bind": BIND},
}


def safety_floors() -> list[tuple[str, bool]]:
    """Assert the configured values are safe, not merely that they are applied.

    Every check in `main` compares the merged result against the role's own
    defaults, so all of them pass no matter what those defaults say. Setting
    `dc_sandbox_mode: "off"` satisfies "sandbox.mode overridden to off" and the
    suite stays green — a mechanism test wearing a governance test's clothes.

    These floors are the governance half: absolute bounds that hold regardless
    of configuration, so widening a control past the profile fails here rather
    than shipping quietly.
    """
    return [
        ("FLOOR sandbox is not disabled", SANDBOX_MODE != "off"),
        ("FLOOR sandbox covers every agent", SANDBOX_MODE == "all"),
        ("FLOOR workspace is not writable", WORKSPACE in ("none", "ro")),
        ("FLOOR gateway is not a wildcard bind", BIND not in ("0.0.0.0", "::", "")),
        # exec and write are the mutating core; a deny list without them is not
        # a read-only profile whatever else it contains.
        ("FLOOR exec is denied", "exec" in DENY),
        ("FLOOR write is denied", "write" in DENY),
        ("FLOOR elevated is disabled", DEFAULTS.get("dc_tools_elevated_enabled") is False),
        # A populated allow-list silently blocks everything outside it, making
        # the effective policy something other than the declared deny list.
        ("FLOOR allow-list stays inactive", ALLOW == []),
        ("FLOOR fail-closed is on", DEFAULTS.get("dc_fail_closed") is True),
    ]


def schema_floors() -> list[tuple[str, bool]]:
    """Every value the overlay writes must satisfy OpenClaw's own schema.

    The floors above are Decision Crafters policy: is this value safe. These are
    a different question: is this value *legal*. `gateway.bind: "127.0.0.1"` was
    perfectly safe and completely illegal — bind is an enum — and it passed
    every check this file had until it crash-looped the daemon.

    Checked against a fixture distilled from `openclaw config schema`, so CI can
    run it without OpenClaw installed. The role itself re-checks against the
    live schema at apply time; this is the earlier, cheaper tripwire.
    """
    fixture = json.loads((ROLE / "files" / "schema-keys.json").read_text())
    paths = fixture["paths"]

    def legal(dotted: str, value: object) -> bool:
        spec = paths.get(dotted)
        if spec is None or not spec.get("exists"):
            return False
        allowed = spec.get("enum")
        return True if allowed is None else value in allowed

    return [
        ("SCHEMA gateway.bind is a legal enum value", legal("gateway.bind", BIND)),
        ("SCHEMA sandbox.mode is a legal enum value", legal("agents.defaults.sandbox.mode", SANDBOX_MODE)),
        ("SCHEMA sandbox.scope is a legal enum value", legal("agents.defaults.sandbox.scope", SCOPE)),
        ("SCHEMA workspaceAccess is a legal enum value", legal("agents.defaults.sandbox.workspaceAccess", WORKSPACE)),
        ("SCHEMA tools.exec.mode is a legal enum value", legal("tools.exec.mode", EXEC_MODE)),
        ("SCHEMA docker.network key exists", legal("agents.defaults.sandbox.docker.network", DOCKER_NETWORK)),
        ("SCHEMA tools.deny key exists", legal("tools.deny", DENY)),
        ("SCHEMA tools.elevated.enabled key exists", legal("tools.elevated.enabled", False)),
        # The regression this file exists to prevent recurring.
        ("SCHEMA an IP address is rejected for gateway.bind", not legal("gateway.bind", "127.0.0.1")),
        ("SCHEMA an invented key is rejected", not legal("gateway.totallyMadeUp", True)),
    ]


def main() -> int:
    merged = combine_recursive(ONBOARDED, OVERLAY)
    sandbox = merged["agents"]["defaults"]["sandbox"]
    tools = merged["tools"]

    checks: list[tuple[str, bool]] = safety_floors() + schema_floors() + [
        # Governance wins over permissive onboarding values.
        ("sandbox.mode overridden off -> %s" % SANDBOX_MODE, sandbox["mode"] == SANDBOX_MODE),
        ("workspaceAccess overridden rw -> %s" % WORKSPACE, sandbox["workspaceAccess"] == WORKSPACE),
        ("workspaceAccess is never rw", sandbox["workspaceAccess"] != "rw"),
        ("elevated.enabled overridden true -> false", tools["elevated"]["enabled"] is False),
        ("gateway.bind overridden 0.0.0.0 -> %s" % BIND, merged["gateway"]["bind"] == BIND),
        ("gateway.bind is never a wildcard", merged["gateway"]["bind"] != "0.0.0.0"),
        ("every governed tool is denied", all(t in tools["deny"] for t in DENY)),
        # The defect this file was written to catch.
        ("no ungoverned allow-list survives", tools.get("allow", []) == ALLOW),
        # Everything outside the governance surface is left alone.
        ("agent model preserved", merged["agents"]["defaults"]["model"] == "anthropic/claude-sonnet-4"),
        ("agent entries preserved", merged["agents"]["entries"][0]["id"] == "main"),
        ("channel credentials preserved", merged["channels"]["telegram"]["token"] == "KEEP-ME"),
        ("unrelated gateway keys preserved", merged["gateway"]["port"] == 18789),
        ("unrelated top-level keys preserved", merged["session"]["historyLimit"] == 50),
    ]

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    if failed:
        print(f"\n{len(failed)} merge-contract check(s) failed.")
        return 1
    print(f"\nAll {len(checks)} merge-contract checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
