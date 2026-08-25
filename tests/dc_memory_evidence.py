#!/usr/bin/env python3
"""Contract tests for the TASK-226 memory-posture evidence.

    python3 tests/dc_memory_evidence.py

WHY THIS FILE EXISTS

memory_posture.py decides whether the captured evidence agrees with an ACCEPTED
founder decision. A wrong answer here does not produce a bug report -- it
produces a closed governance task resting on a misread.

Three specific misreads are available, and each produces output that looks
clean:

  THE PROVIDER TRAP    `memorySearch.provider` unset rendered as a blank. The
                       live schema documents it as defaulting to `openai`, and
                       the accepted posture is local-first. A blank hides an
                       external data path inside the posture that was accepted
                       as the local one.

  THE ABSENCE TRAP     `memory-core` appears nowhere in the config schema and
                       WAS in the 2026-08-16 enabled list. Reading absence from
                       the schema as absence from the host inverts the fact.
                       Symmetrically, a schema-declared `active-memory` entry
                       read as "installed" invents one.

  THE FLOOR            scoring a posture from a `plugins inspect` that timed
                       out. `plugins list` hung on this build once and was
                       recorded as the subcommand not existing.

Each is reproduced below and asserted to fail. A control that has never been
observed to fail has not been tested.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "roles" / "dc-governed-config"
READER = ROLE / "files" / "memory_posture.py"


def base_evidence(**over) -> dict:
    ev = {
        "effective": {
            "memory": "",
            "agents.defaults.memorySearch.enabled": "",
            "agents.defaults.memorySearch.provider": "",
            "agents.defaults.memorySearch.extraPaths": "[]",
            "agents.defaults.memorySearch.experimental.sessionMemory": "",
            "agents.defaults.memorySearch.multimodal.enabled": "",
        },
        "per_agent": {},
        "inspect": {"state": "VERIFIED HOST",
                    "stdout": "memory-core\norigin: bundled",
                    "in_enumeration": True},
        "configured_plugin_entries": ["firecrawl", "ollama", "slack"],
        "memory_dir": {"path": "/w/dc-research/memory", "exists": True,
                       "owner": "openclaw", "mode": "0700"},
    }
    ev.update(over)
    return ev


def run(ev: dict | str) -> tuple[int, str, str]:
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "e.json"
        f.write_text(ev if isinstance(ev, str) else json.dumps(ev))
        p = subprocess.run(
            [sys.executable, str(READER), "--evidence", str(f)],
            capture_output=True, text=True, timeout=120)
        return p.returncode, p.stdout, p.stderr


def main() -> int:
    checks: list[tuple[str, bool]] = []
    if not READER.exists():
        print(f"FAIL  reader missing at {READER}")
        return 1

    # --- 1. THE PROVIDER TRAP ------------------------------------------------
    rc, out, _ = run(base_evidence())
    checks.append((
        "unset provider is reported as the DOCUMENTED DEFAULT, not as blank",
        "DEFAULT NOBODY CHOSE" in out and "openai" in out))
    checks.append((
        "unset provider is never rendered as 'not configured' and left there",
        "Unset does NOT mean unused" in out))

    # enabled + unset provider = the documented external default is LIVE
    ev = base_evidence()
    ev["effective"]["agents.defaults.memorySearch.enabled"] = "true"
    rc_on, out_on, _ = run(ev)
    checks.append((
        "memorySearch ENABLED with unset provider is a finding, not a blank",
        "would leave this host" in out_on and rc_on == 1))

    # enabled false = inert, but STILL an unchosen default
    ev = base_evidence()
    ev["effective"]["agents.defaults.memorySearch.enabled"] = "false"
    rc_off, out_off, _ = run(ev)
    checks.append((
        "memorySearch OFF reports the default inert but still unchosen",
        "inert today" in out_off and "unchosen default" in out_off))

    # both unset = UNKNOWN, and explicitly NOT exposure
    checks.append((
        "provider and enabled both unset is UNKNOWN, explicitly not exposure",
        "NOT a finding of exposure" in out
        and "could not have told you either way" in out))

    # a configured LOCAL provider must not be flagged
    ev = base_evidence()
    ev["effective"]["agents.defaults.memorySearch.provider"] = "ollama"
    rc_l, out_l, _ = run(ev)
    checks.append((
        "a configured local provider is CONFIGURED/LOCAL, not a finding",
        "CONFIGURED: ollama  (LOCAL)" in out_l and "external" not in out_l.lower()))

    # a configured EXTERNAL provider must be flagged on posture grounds
    ev = base_evidence()
    ev["effective"]["agents.defaults.memorySearch.provider"] = "gemini"
    rc_x, out_x, _ = run(ev)
    checks.append((
        "a configured external provider is a finding against the posture",
        "(EXTERNAL)" in out_x and "local-first" in out_x and rc_x == 1))

    # a PER-AGENT override must win over defaults -- reading only defaults
    # reports a posture the governed agent does not run under
    ev = base_evidence()
    ev["effective"]["agents.defaults.memorySearch.provider"] = "ollama"
    ev["per_agent"] = {"dc-research": {"memorySearch.provider": "openai"}}
    rc_pa, out_pa, _ = run(ev)
    checks.append((
        "a per-agent provider override overrides the defaults value",
        "per-agent override on dc-research" in out_pa and "(EXTERNAL)" in out_pa))

    # --- 2. THE ABSENCE TRAP -------------------------------------------------
    checks.append((
        "a plugin with no plugins.entries block is not read as absent/disabled",
        "not thereby absent or disabled" in out
        and "Receipt A above is the authority" in out))
    checks.append((
        "a CONFIGURED entry is not read as proof the plugin is loaded",
        "not proof the plugin is loaded" in out and "firecrawl" in out))
    # PROVENANCE. The first version named this field `schema_plugin_entries`
    # and the report said "the schema DOES declare", while the play fed it from
    # `config get plugins.entries` -- the effective config. An evidence artifact
    # that misnames its source is worse than one that omits it, because the
    # wrong source is quotable.
    checks.append((
        "REGRESSION: the entries list names its real source, not the schema",
        "effective config -- NOT the schema" in out
        and "plugin entries the schema DOES declare" not in out))

    # --- 3. THE FLOOR --------------------------------------------------------
    ev = base_evidence(inspect={"state": "timed out", "stdout": "",
                                "in_enumeration": True})
    rc_t, out_t, _ = run(ev)
    checks.append((
        "a timed-out inspect is INDETERMINATE, never 'plugin absent'",
        "INDETERMINATE" in out_t and "NOT a finding that" in out_t))
    checks.append((
        "the posture is not scored from an inspection that did not complete",
        "posture is not scored" in out_t))

    ev = base_evidence()
    ev["inspect"]["in_enumeration"] = False
    rc_e, out_e, _ = run(ev)
    checks.append((
        "a target absent from the enumeration is reported, not silently passed",
        "did not appear in the ENABLED" in out_e and rc_e == 1))

    rc_b, _, err_b = run("{not json")
    checks.append((
        "unreadable evidence returns rc=2 INSUFFICIENT EVIDENCE",
        rc_b == 2 and "INSUFFICIENT EVIDENCE" in err_b))
    rc_n, _, err_n = run({"effective": {}})
    checks.append((
        "empty effective config is refused rather than reported as clean",
        rc_n == 2 and "inference from silence" in err_n))

    # --- 4. the surfaces required to default closed --------------------------
    ev = base_evidence()
    ev["effective"]["agents.defaults.memorySearch.extraPaths"] = '["/srv/other"]'
    rc_o, out_o, _ = run(ev)
    checks.append((
        "an open extraPaths is a finding",
        "OPEN: extra indexed paths" in out_o and rc_o == 1))
    ev = base_evidence()
    ev["effective"]["agents.defaults.memorySearch.experimental.sessionMemory"] = "true"
    _, out_s, _ = run(ev)
    checks.append((
        "an open sessionMemory is a finding",
        "OPEN: session transcript indexing" in out_s))

    ev = base_evidence()
    ev["memory_dir"]["owner"] = "root"
    rc_r, out_r, _ = run(ev)
    checks.append((
        "a root-owned memory directory is a finding (silent write failure)",
        "root-owned" in out_r and "SILENTLY" in out_r and rc_r == 1))

    # --- 5. criterion 5 is fixed and cannot be talked out of ----------------
    for label, text in (("clean run", out), ("finding run", out_x),
                        ("indeterminate run", out_t)):
        checks.append((
            f"criterion 5 says NOT SATISFIABLE on a {label}",
            "NOT SATISFIABLE AS SPECIFIED" in text))
        checks.append((
            f"criterion 5 disclaims being a behavioural proof on a {label}",
            "NOT A BEHAVIOURAL ISOLATION PROOF" in text))
    checks.append((
        "a zero-finding run is explicitly not a proof of isolation",
        "does NOT mean isolation was proven" in out))
    checks.append((
        "criterion 5 names the reason: two coordinates, one agent, the cap",
        "one-pilot-per-quarter cap" in out and "Only `dc-research`" in out))
    checks.append((
        "criterion 5 flags TASK-230's 'deterministic' wording as unsupported",
        "deterministic cross-coordinate" in out and "carry that flag" in out))

    # --- 6. zero mutation, asserted rather than assumed ----------------------
    for tf in ("memory_evidence.yml", "plugin_inspect.yml"):
        play = (ROLE / "tasks" / tf).read_text()
        for verb in ("'patch'", "'set'", "'unset'", "--fix", "notify:",
                     "flush_handlers", "ansible.builtin.systemd"):
            checks.append((f"{tf} never uses {verb}", verb not in play))
        checks.append((
            f"{tf} closes stdin on every command (the hang precedent)",
            play.count("argv:") <= play.count('stdin: ""') + 1))

    mem = (ROLE / "tasks" / "memory_evidence.yml").read_text()
    checks.append((
        "memory_evidence tolerates rc=1 (findings) and fails only on rc=2",
        "not in [0, 1]" in mem))
    checks.append((
        "memory_evidence says INSUFFICIENT EVIDENCE must not close the task",
        "must not be closed from it" in mem))
    checks.append((
        "memory_evidence delegates receipt A to the generic plugin play",
        "tasks_from" not in mem and "plugin_inspect.yml" in mem))

    # --- 7. the generic play cannot inspect a set nobody chose ---------------
    import yaml
    d = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
    checks.append((
        "dc_plugin_inspect_targets defaults to empty",
        d.get("dc_plugin_inspect_targets") == []))
    checks.append((
        "the memory paths are in the STANDING audit, not only this play",
        any(p.startswith("agents.defaults.memorySearch") for p in d["dc_audit_paths"])
        and "memory" in d["dc_audit_paths"]))
    probes = {p["name"]: p.get("requires", []) for p in d["dc_cli_surface_probes"]}
    checks.append((
        "the CLI surface now requires the plugins subverbs it depends on",
        "inspect" in probes.get("plugins", []) and "list" in probes.get("plugins", [])))

    # --- 8. REGRESSION: the two bugs the first host run exposed --------------
    #
    # 2026-08-25, first real invocation. Both produced output that read as a
    # result rather than as a failure, which is why both are pinned here.

    import re
    pi = (ROLE / "tasks" / "plugin_inspect.yml").read_text()

    # BUG 1 -- the parser anchored at line start and matched nothing, because
    # every line of `plugins list --verbose` begins with `@` or two spaces. The
    # receipt then said `enumeration=VERIFIED HOST | plugins_enumerated=0`
    # against a host running 50. Reads as "no plugins are enabled"; means "the
    # parser failed". The regex is extracted from the task file and run against
    # the real output shape, so a future edit cannot quietly break it again.
    m = re.search(r"regex_findall\('([^']*enabled[^']*)'\)", pi)
    checks.append(("the enumeration regex is present in the task file", bool(m)))
    if m:
        pattern = m.group(1).replace("\\\\", "\\")
        real = ("Plugins (50/50 enabled)\n"
                "@openclaw/alibaba-provider (alibaba) enabled\n"
                "  format: openclaw\n  origin: bundled\n\n"
                "@openclaw/memory-core (memory-core) enabled\n  origin: bundled\n")
        found = sorted(set(re.findall(pattern, real)))
        checks.append((
            "REGRESSION: the regex parses the REAL `plugins list` output shape",
            found == ["alibaba", "memory-core"]))

    checks.append((
        "REGRESSION: rc=0 with zero names parsed is refused as IMPOSSIBLE",
        "impossible on a running Gateway" in pi
        and "(dc_pi_names | length) == 0" in pi))
    checks.append((
        "REGRESSION: that refusal is fail-closed, not a debug line",
        "ansible.builtin.fail" in pi.split("Refuse an enumeration")[1][:400]))
    checks.append((
        "a partial parse is cross-checked against the runtime's own total",
        "PARTIAL PARSE" in pi and "dc_pi_declared_total" in pi))

    # BUG 2 -- `a + [{}] | first` binds `| first` to the literal, not the sum.
    # It failed at ARG FINALIZATION, which runs before `failed_when` can see it,
    # so the play aborted. Fail-closed did its job; the expression was still
    # wrong. Asserted structurally because the templating is not exercised here.
    # Comment lines are stripped before matching. The first version of this
    # check searched the whole file and tripped on this task's OWN comment,
    # which quotes the broken form to explain it -- a check that fires on the
    # documentation of the property it verifies is not a check. Same class as
    # the `restart` false positive in dc_schema_surface.py.
    mem_code = "\n".join(l for l in mem.splitlines()
                         if not l.lstrip().startswith("#"))
    checks.append((
        "REGRESSION: the inspect-isolation expression parenthesises the sum",
        "+ [{}]) | first" in mem_code and "+ [{}] | first" not in mem_code))

    # --- 9. every dc_ variable a play references must be resolvable ----------
    #
    # THE BUG CLASS THIS CATCHES, which has now bitten three times:
    #
    #   `dc_agent_workspace_root` did not exist. It was composed into a
    #   `path:` argument, and an undefined variable there fails at ARG
    #   FINALIZATION -- which runs BEFORE `failed_when` can see it, so no
    #   amount of `failed_when: false` protects against it. The play aborted
    #   mid-run against the real host.
    #
    #   `ansible-lint` does not catch it. `--syntax-check` does not catch it.
    #   Only running the play against a host does, which makes it the most
    #   expensive possible way to find a typo.
    #
    # So: collect every `dc_*` reference in the task files, and require each to
    # be either declared in defaults or set_fact'd somewhere in the role. This
    # is a spelling check, not a type check, and that is exactly the failure.
    import re as _re
    declared = set(d.keys())
    role_tasks = sorted((ROLE / "tasks").glob("*.yml"))
    for tf in role_tasks:
        body = tf.read_text()
        declared |= set(_re.findall(r"^\s{4}(dc_[a-z0-9_]+):", body, _re.M))
        declared |= set(_re.findall(r"^\s+(dc_[a-z0-9_]+):\s", body, _re.M))
        declared |= set(_re.findall(r"register:\s+(dc_[a-z0-9_]+)", body))
        declared |= set(_re.findall(r"loop_var:\s+(dc_[a-z0-9_]+)", body))

    unresolved: list[str] = []
    for tf in (ROLE / "tasks" / "memory_evidence.yml",
               ROLE / "tasks" / "plugin_inspect.yml"):
        body = tf.read_text()
        code = "\n".join(l for l in body.splitlines()
                          if not l.lstrip().startswith("#"))
        for ref in set(_re.findall(r"\bdc_[a-z0-9_]+", code)):
            if ref not in declared:
                unresolved.append(f"{tf.name}: {ref}")
    checks.append((
        "REGRESSION: every dc_ variable the new plays reference is resolvable "
        f"({'; '.join(sorted(unresolved)) if unresolved else 'all resolved'})",
        not unresolved))

    # mem_code, not mem. This check has now been written against the raw file
    # twice and tripped on the comment naming the bug both times. Any assertion
    # of the form "the broken form is absent" MUST run against comment-stripped
    # code, because the file documents the broken form on purpose.
    checks.append((
        "REGRESSION: the workspace is READ from agents.list, not composed",
        "map(attribute='workspace'" in mem_code
        and "dc_agent_workspace_root" not in mem_code))
    checks.append((
        "an agent with no declared workspace is reported as a finding",
        "declares no workspace" in mem and "write destination is UNKNOWN" in mem))
    checks.append((
        "REGRESSION: entry names are parsed as top-level keys, not swept "
        "from nested sub-keys",
        "from_json).keys()" in mem_code and "regex_findall('\"(" not in mem_code))

    failed = [n for n, ok in checks if not ok]
    for n, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {n}")
    if failed:
        print(f"\n{len(failed)} memory-evidence check(s) failed.")
        return 1
    print(f"\nAll {len(checks)} memory-evidence checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
