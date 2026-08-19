#!/usr/bin/env python3
"""Contract tests for the Slack routing binding composed by slack_rebind.yml.

    python3 tests/dc_slack_binding.py

WHY THIS FILE EXISTS

On 2026-08-17 a binding was composed, validated, patched into the config and
displayed by `openclaw agents bindings` -- and matched nothing. Every signal the
role can read said success. The only symptom was that messages kept reaching the
default agent, which is also what happens when no binding exists at all.

Two independent defects produced that, and both are silent by construction:

  1. `peer.id` for a DM was the D... IM CONVERSATION id. Routing never sees one:
     the Slack boundary builds peer.id from the sending USER, so the comparison
     is against a U... id and a D... binding can never match.

  2. `accountId` was omitted, which reads as "any account" and is not. An absent
     accountId normalises to the literal string "default"; bindings are bucketed
     by account BEFORE peer matching, so on any account not named "default" the
     peer tier is never evaluated.

Neither is visible in a diff, a schema validation, or a config read-back. The
guards added to slack_rebind.yml are the only thing standing between a future
edit and the same silence, so they are tested here rather than trusted.

WHAT THIS TESTS, AND WHAT IT DOES NOT

It renders the REAL Jinja expression, extracted from the real task file, through
Jinja2 with Ansible's `match` test registered. It is not a reimplementation of
the mapping -- reimplementing it would only prove the copy agrees with itself.

It cannot prove the runtime matches the binding. That is behavioural and closes
only by asking the responder which agent it is. See the receipt.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from jinja2 import Environment

# Synthetic fixtures, CONSTRUCTED rather than written as literals.
#
# This file is tracked in a PUBLIC repository, and the merge-contract secret
# scanner correctly refuses Slack-shaped identifier literals in tracked files.
# These are obviously fake to a human and indistinguishable from real to a
# regex. Building them keeps the file genuinely free of identifier literals,
# which is what the scanner protects; adding this path to an exemption list
# would instead protect the file from the scanner.
#
# The prefix is the only part the code under test reads: C -> channel,
# G -> group, U -> direct.
CHAN = "C" + "0" * 6 + "CHANNEL"
USER = "U" + "0" * 6 + "USER00"
GROUP = "G" + "0" * 6 + "GROUP0"

ROLE = Path(__file__).resolve().parent.parent / "roles" / "dc-governed-config"
REBIND = ROLE / "tasks" / "slack_rebind.yml"
DEFAULTS = ROLE / "defaults" / "main.yml"


def _ansible_env() -> Environment:
    """Jinja2 with the Ansible tests the expression actually uses.

    `match` anchors at the start of the string; `search` does not. Getting that
    backwards here would make the test agree with a wrong implementation.
    """
    env = Environment()
    env.tests["match"] = lambda value, pattern: re.match(pattern, value) is not None
    env.tests["search"] = lambda value, pattern: re.search(pattern, value) is not None
    return env


def _tasks() -> list[dict]:
    return yaml.safe_load(REBIND.read_text())


def _task(name_fragment: str) -> dict | None:
    for task in _tasks():
        if name_fragment.lower() in str(task.get("name", "")).lower():
            return task
    return None


def _write_index() -> int:
    """Position of the task that actually mutates the config.

    Located by name rather than by module: several tasks in this file invoke the
    same `command` module, and one of them is the read-only `--dry-run`
    validation. A guard that sits between the dry run and the write would look
    correctly ordered against the wrong landmark.
    """
    for i, task in enumerate(_tasks()):
        if str(task.get("name", "")).strip() == "Write the bindings":
            return i
    return -1


def _compose_expression() -> str:
    task = _task("Build one binding per required conversation")
    assert task is not None, "the compose task is missing from slack_rebind.yml"
    # The role uses FQCNs throughout; accept either spelling so this test does
    # not become the reason someone avoids a rename.
    module = task.get("ansible.builtin.set_fact") or task.get("set_fact")
    assert module is not None, "the compose task no longer uses set_fact"
    return module["dc_rb_entries"]


def _render(conversations: list[str], account_id: str = "*") -> list[dict]:
    """Run the real expression once per item, as the Ansible loop does."""
    env = _ansible_env()
    template = env.from_string(_compose_expression())
    entries: list[dict] = []
    for item in conversations:
        rendered = template.render(
            dc_rb_entries=entries,
            dc_agent_id="dc-research",
            dc_slack_binding_account_id=account_id,
            item=item,
        )
        entries = yaml.safe_load(rendered)
    return entries


def main() -> int:
    checks: list[tuple[str, bool]] = []

    # --- the mapping itself, rendered from the real expression --------------
    entries = _render([CHAN, USER, GROUP])
    by_id = {e["match"]["peer"]["id"]: e for e in entries}

    def kind(peer_id: str) -> str | None:
        return by_id.get(peer_id, {}).get("match", {}).get("peer", {}).get("kind")

    checks += [
        ("one binding composed per conversation", len(entries) == 3),
        ("C... maps to kind channel", kind(CHAN) == "channel"),
        # The defect. A DM is keyed on the USER, and `direct` must follow U...
        # rather than the D... id that reads like the obvious choice.
        ("U... maps to kind direct", kind(USER) == "direct"),
        ("G... maps to kind group", kind(GROUP) == "group"),
        ("every entry names the agent",
         all(e["agentId"] == "dc-research" for e in entries)),
        ("every entry is channel slack",
         all(e["match"]["channel"] == "slack" for e in entries)),
    ]

    # --- accountId, the invisible bucket ------------------------------------
    # Read defensively. A missing key is a FAILING CHECK, not a traceback: the
    # two defects this file exists for occurred together, and a test that dies
    # on the first one would have reported only half the problem.
    checks += [
        ("every entry carries accountId",
         all("accountId" in e["match"] for e in entries)),
        ("accountId is not silently empty",
         all(e["match"].get("accountId") not in ("", None) for e in entries)),
        ("accountId is threaded from the variable, not hardcoded",
         all(e["match"].get("accountId") == "acct-explicit"
             for e in _render([CHAN], account_id="acct-explicit"))),
    ]

    # Omitting accountId normalises to the literal "default" in the runtime.
    # This asserts the role never ships that shape by accident.
    checks.append((
        "default account id is the wildcard, not the literal 'default'",
        re.search(r'^dc_slack_binding_account_id:\s*"\*"\s*$',
                  DEFAULTS.read_text(), re.M) is not None,
    ))

    # --- id casing ----------------------------------------------------------
    # Matching is case-sensitive on a trim-only comparison and Slack emits
    # uppercase. Session keys are lowercased AFTER routing; "fixing" the case to
    # match them breaks the binding. This catches a well-intentioned edit.
    checks.append((
        "ids are passed through without case folding",
        all(e["match"]["peer"]["id"].isupper() for e in entries)
        and "lower" not in _compose_expression(),
    ))

    # --- the guards ---------------------------------------------------------
    d_guard = _task("Refuse a DM conversation id")
    prefix_guard = _task("Refuse an unrecognised Slack id prefix")

    expansion_guard = _task("Refuse to route a channel that is not an authorized")
    orphan_dm_guard = _task("Refuse when an authorized DM has no routing peer")

    checks += [
        ("a D... conversation id is refused", d_guard is not None),
        ("an unknown id prefix is refused", prefix_guard is not None),
        # The two lists must keep describing the same conversations. These are
        # the price of splitting reachability from routing.
        ("routing a channel outside the authorized list is refused",
         expansion_guard is not None),
        ("an authorized DM with no routing peer is refused",
         orphan_dm_guard is not None),
        # Routing must iterate the ROUTING list, not the reachability one --
        # the collapse the split exists to prevent. Checked on the compose
        # task's `loop` specifically: the coherence guards below legitimately
        # mention both lists, so a text search over the file would pass or fail
        # for the wrong reason.
        ("the compose task loops over dc_slack_route_peers",
         "dc_slack_route_peers" in str(
             (_task("Build one binding per required conversation") or {}).get("loop", ""))),
    ]

    for label, guard in (("D... guard", d_guard), ("prefix guard", prefix_guard),
                         ("expansion guard", expansion_guard),
                         ("orphan-DM guard", orphan_dm_guard)):
        # A guard that runs after the write, or that is skipped when
        # fail-closed is on, is decoration. Both were real risks here.
        checks.append((
            f"{label} is fail-closed",
            guard is not None and any("dc_fail_closed" in str(c)
                                      for c in guard.get("when", [])),
        ))
        checks.append((
            f"{label} runs before the config is written",
            guard is not None
            and guard is not None and _write_index() >= 0
            and _tasks().index(guard) < _write_index(),
        ))

    # --- the shape assertion ------------------------------------------------
    shape = _task("Confirm the composed bindings are well formed")
    shape_text = yaml.safe_dump(shape) if shape else ""
    checks += [
        ("the shape assertion checks accountId is present",
         "accountId" in shape_text),
        ("the shape assertion rejects a D... id reaching the payload",
         "'^D'" in shape_text or '"^D"' in shape_text),
    ]

    # --- every config write must notify the restart handler -----------------
    #
    # THE DEFECT THIS FILE EXISTS FOR, GENERALISED.
    #
    # `bindings` is read by the Gateway at startup. slack_rebind.yml patched it,
    # validated it, read it back, asserted success -- and the running process
    # kept its old routing table for a full day while four other theories were
    # investigated. Four sibling task files notified the restart handler; this
    # one was written as a separate play and lost the handler in the split.
    #
    # Checked across ALL task files rather than the two known ones, because the
    # next omission will be in whichever file nobody is thinking about. A config
    # write with no restart is a change that reports success and does nothing.
    HANDLER = "Restart openclaw gateway"
    unnotified: list[str] = []
    for path in sorted((ROLE / "tasks").glob("*.yml")):
        try:
            tasks = yaml.safe_load(path.read_text()) or []
        except yaml.YAMLError:
            unnotified.append(f"{path.name}:UNPARSEABLE")
            continue
        if not isinstance(tasks, list):
            continue
        for task in tasks:
            if not isinstance(task, dict):
                continue
            cmd = task.get("ansible.builtin.command") or task.get("command") or {}
            argv = str(cmd.get("argv", "")) if isinstance(cmd, dict) else ""
            # `config patch` is the only verb in this role that mutates config.
            # `get`, `validate` and `schema` are reads and must NOT restart.
            #
            # `patch --dry-run` is ALSO a read -- it asks the runtime whether a
            # change would be legal and writes nothing. Requiring a restart
            # there would restart the Gateway on every dry run, turning the
            # safe rehearsal into the more dangerous operation. Excluded
            # explicitly rather than by hoping no such task exists.
            is_write = "'patch'" in argv and "--dry-run" not in argv
            # A write may satisfy the rule two ways. The deferred HANDLER is the
            # norm. But a synthetic harness must observe the effective state in
            # the same run, and a handler fires only at end-of-play -- too late
            # to verify against. An explicit `gateway restart` LATER IN THE SAME
            # FILE satisfies the intent more strictly than the handler does,
            # because it is immediate rather than deferred.
            #
            # "Later in the same file" matters: a restart BEFORE the write would
            # leave the process stale exactly as an omitted handler does.
            restarts_inline = any(
                "'restart'" in str(
                    (later.get("ansible.builtin.command") or later.get("command") or {}).get("argv", ""))
                and "'gateway'" in str(
                    (later.get("ansible.builtin.command") or later.get("command") or {}).get("argv", ""))
                for later in tasks[tasks.index(task) + 1:]
                if isinstance(later, dict)
            )
            if is_write and str(task.get("notify", "")) != HANDLER and not restarts_inline:
                unnotified.append(f"{path.name}: {task.get('name', '?')}")

    checks.append((
        "every `config patch` notifies the restart handler",
        not unnotified,
    ))
    if unnotified:
        for entry in unnotified:
            print(f"        unnotified write -> {entry}")

    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    if failed:
        print(f"\n{len(failed)} Slack-binding check(s) failed.")
        return 1
    print(f"\nAll {len(checks)} Slack-binding checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
