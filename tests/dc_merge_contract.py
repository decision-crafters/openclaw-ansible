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
        "dc_plugins_deny", "dc_plugins_allow", "dc_plugins_required",
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
PLUGINS_DENY = DEFAULTS["dc_plugins_deny"]
PLUGINS_ALLOW = DEFAULTS["dc_plugins_allow"]
PLUGINS_REQUIRED = DEFAULTS["dc_plugins_required"]

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
    "session": {"historyLimit": 50},
    # Mirrors the real host, inspected 2026-08-15. Earlier this modelled Slack's
    # credential under `plugins.entries.slack`, which was a guess and was wrong
    # in an instructive way: Slack registers TWICE. Credentials live under
    # `channels.slack`; `plugins.entries.slack` carries only an enabled flag.
    #
    # Keeping the invented shape would have kept this suite green while testing
    # a config the host does not have.
    "channels": {
        "telegram": {"token": "KEEP-ME"},
        "slack": {
            "enabled": True,
            "botToken": "xoxb-KEEP-ME-TOO-000000000000000000000000",
            "appToken": "xapp-AND-ME-00000000000000000000000000000",
            "groupPolicy": "open",
            "capabilities": {"interactiveReplies": True},
        },
    },
    "plugins": {
        "entries": {
            "ollama": {"enabled": True},
            "slack": {"enabled": True},
            # Enabled AND provisioned with a live key on the host. deny must win
            # over this, which is the documented precedence.
            "firecrawl": {"enabled": True,
                          "config": {"webSearch": {"apiKey": "fc-KEEP-OUT"}}},
        },
    },
}

OVERLAY: dict[str, Any] = {
    "agents": {"defaults": {"sandbox": {
        "mode": SANDBOX_MODE, "scope": SCOPE, "workspaceAccess": WORKSPACE,
        "docker": {"network": DOCKER_NETWORK}}}},
    "tools": {"allow": ALLOW, "deny": DENY, "exec": {"mode": EXEC_MODE},
              "elevated": {"enabled": False}},
    "gateway": {"bind": BIND},
    # plugins.allow is written ONLY when non-empty, mirroring tasks/main.yml.
    # An empty list is not written, because the host has no such key and the
    # empty-list semantics for plugins are undocumented — writing [] would
    # assert a meaning rather than apply a control. deny alone is sufficient.
    "plugins": ({"deny": PLUGINS_DENY} if not PLUGINS_ALLOW
                else {"deny": PLUGINS_DENY, "allow": PLUGINS_ALLOW}),
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
    ] + availability_floors()


def availability_floors() -> list[tuple[str, bool]]:
    """Floors that fail when a capability is REMOVED, not when one is admitted.

    Every other check in this file runs one direction: it fails if something
    permissive survived. These run the other way, and nothing here had a check
    of this shape before 2026-08-15.

    The founder decision that day made Slack the operator's only route to a
    loopback-bound Gateway until Tailscale exists, and stated that TASK-217 must
    not disable it to simplify plugin security. Denying it would be legal
    config, would pass the schema, would pass every assertion in verify.yml, and
    would leave a healthy Gateway nobody could reach. There is no technical
    signal for that failure — the only thing making it wrong is the decision, so
    the decision is what gets pinned.

    Note the last floor. Without it the one above is trivially satisfiable by
    deleting `slack` from dc_plugins_required, which is the obvious move for
    someone trying to get a red suite green and has no idea what it costs.
    """
    return [
        ("FLOOR firecrawl is denied", "firecrawl" in PLUGINS_DENY),
        # Deny wins over allow and over per-plugin enablement, so an entry here
        # is final — including when it is the wrong entry.
        ("FLOOR no required plugin is denied",
         not set(PLUGINS_DENY) & set(PLUGINS_REQUIRED)),
        # An exclusive allowlist gating ~49 bundled plugins denies by omission.
        # Empty keeps deny as the whole policy; populated is a lockout waiting
        # for someone to forget an entry.
        ("FLOOR plugin allow-list stays inactive", PLUGINS_ALLOW == []),
        ("FLOOR slack remains a required capability", "slack" in PLUGINS_REQUIRED),
        ("FLOOR a model provider remains available", "ollama" in PLUGINS_REQUIRED),
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
        ("SCHEMA plugins.deny key exists", legal("plugins.deny", PLUGINS_DENY)),
        ("SCHEMA plugins.allow key exists", legal("plugins.allow", PLUGINS_ALLOW)),
    ]


def validator_floors() -> list[tuple[str, bool]]:
    """The overlay validator must reject invented keys AND accept dynamic maps.

    It failed the second half on 2026-08-16: `channels.slack.channels` is keyed
    by Slack channel ID, so the schema declares no named properties for it, and
    the validator read every ID as an invented key. It refused a correct config
    with "no such key in the schema. Available at this level: []".

    A false rejection is not a safe failure. It teaches the operator that the
    gate cries wolf, and the next genuine rejection gets argued with instead of
    read. Both directions are pinned here because fixing one by loosening the
    other would be worse than the original bug.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "validate_overlay", ROLE / "files" / "validate_overlay.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    schema = {
        "properties": {
            "gateway": {"properties": {"bind": {"enum": ["auto", "loopback"]}}},
            "channels": {"properties": {"slack": {"properties": {
                "groupPolicy": {"enum": ["open", "disabled", "allowlist"]},
                "channels": {"type": "object"},
            }}}},
        }
    }

    def check(overlay) -> int:
        errors: list[str] = []
        module.walk(overlay, schema, {}, [], errors)
        return len(errors)

    # agents.list mirrors the live shape: an array whose items are objects.
    arr_schema = {"properties": {"agents": {"properties": {"list": {
        "type": "array",
        "items": {"properties": {
            "id": {"type": "string"},
            "sandbox": {"properties": {"mode": {"enum": ["off", "non-main", "all"]}}},
        }},
    }}}}}

    def check_arr(overlay) -> int:
        errors: list[str] = []
        module.walk(overlay, arr_schema, {}, [], errors)
        return len(errors)

    return [
        ("VALIDATOR accepts dynamic map keys",
         check({"channels": {"slack": {"channels": {"C0EXAMPLE01": {"requireMention": True}}}}}) == 0),
        ("VALIDATOR accepts enterprise-qualified map keys",
         check({"channels": {"slack": {"channels": {"team:T0A:channel:C0B": {"enabled": True}}}}}) == 0),
        ("VALIDATOR still rejects an invented key in a closed set",
         check({"gateway": {"totallyMadeUp": True}}) == 1),
        ("VALIDATOR still rejects an illegal enum value",
         check({"gateway": {"bind": "127.0.0.1"}}) == 1),
        ("VALIDATOR still rejects an invented key beside a map",
         check({"channels": {"slack": {"nopeNotAKey": 1}}}) == 1),
        # agents.list is an array of objects. The validator walked straight past
        # it and printed "overlay validated against the live schema" for an
        # entry containing an invented key and an illegal enum, because it never
        # looked inside. A check that passes by asking nothing is worse than an
        # absent check: the absent one does not print the word "validated".
        ("VALIDATOR descends into arrays of objects",
         check_arr({"agents": {"list": [{"id": "x", "nopeNotAKey": 1}]}}) == 1),
        ("VALIDATOR catches an illegal enum inside an array item",
         check_arr({"agents": {"list": [{"id": "x", "sandbox": {"mode": "banana"}}]}}) == 1),
        ("VALIDATOR accepts a legal array item",
         check_arr({"agents": {"list": [{"id": "x", "sandbox": {"mode": "all"}}]}}) == 0),
    ]


def main() -> int:
    merged = combine_recursive(ONBOARDED, OVERLAY)
    sandbox = merged["agents"]["defaults"]["sandbox"]
    tools = merged["tools"]

    checks: list[tuple[str, bool]] = safety_floors() + schema_floors() + validator_floors() + [
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
        # Plugin layer. Separate from the tool checks above because it is a
        # separate layer: plugins run in-process with the Gateway, outside the
        # sandbox every other control here depends on.
        ("firecrawl reaches plugins.deny", "firecrawl" in merged["plugins"]["deny"]),
        # Not "an empty allow-list is written" — no allow key is written at all.
        # The host has none, and [] would assert an undocumented meaning against
        # a live daemon. deny wins over allow and over per-plugin enablement, so
        # nothing is lost; an absent key cannot be misread.
        ("no plugin allow-list is introduced",
         PLUGINS_ALLOW != [] or "allow" not in merged["plugins"]),
        # The merge must not deny a required plugin by either route.
        ("slack is not denied", "slack" not in merged["plugins"]["deny"]),
        ("slack is not excluded by omission",
         merged["plugins"].get("allow", []) == [] or "slack" in merged["plugins"]["allow"]),
        # firecrawl is enabled with a live credential on the host, so this is a
        # provisioned capability rather than a dormant one. deny overrides
        # per-plugin enablement, which is the documented precedence.
        ("deny survives alongside per-plugin enablement",
         merged["plugins"]["entries"]["firecrawl"]["enabled"] is True
         and "firecrawl" in merged["plugins"]["deny"]),
        # `combine(recursive=True)` merges dicts key by key, so writing
        # plugins.deny must not replace the whole `plugins` subtree and take
        # `entries` with it. That survives by a property of the merge, and
        # properties that hold by accident stop holding quietly.
        ("plugins.entries survives writing plugins.deny",
         set(merged["plugins"]["entries"]) == {"ollama", "slack", "firecrawl"}),
        ("nested plugin config survives",
         merged["plugins"]["entries"]["firecrawl"]["config"]["webSearch"]["apiKey"] == "fc-KEEP-OUT"),
        # Everything outside the governance surface is left alone.
        ("agent model preserved", merged["agents"]["defaults"]["model"] == "anthropic/claude-sonnet-4"),
        ("agent entries preserved", merged["agents"]["entries"][0]["id"] == "main"),
        ("channel credentials preserved", merged["channels"]["telegram"]["token"] == "KEEP-ME"),
        # The keys the operator's own access depends on. The overlay writes
        # nothing under `channels`, so these survive — but "survives because we
        # never touch it" is a property worth pinning, since the next person to
        # extend this overlay will not know that.
        ("slack bot token preserved",
         merged["channels"]["slack"]["botToken"].startswith("xoxb-KEEP-ME-TOO")),
        ("slack app token preserved",
         merged["channels"]["slack"]["appToken"].startswith("xapp-AND-ME")),
        ("slack channel stays enabled", merged["channels"]["slack"]["enabled"] is True),
        ("slack connector settings untouched",
         merged["channels"]["slack"]["groupPolicy"] == "open"
         and merged["channels"]["slack"]["capabilities"]["interactiveReplies"] is True),
        ("ollama stays enabled", merged["plugins"]["entries"]["ollama"]["enabled"] is True),
        ("slack plugin entry stays enabled",
         merged["plugins"]["entries"]["slack"]["enabled"] is True),
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
