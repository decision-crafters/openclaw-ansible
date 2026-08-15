#!/usr/bin/env python3
"""Reject module/parameter combinations that only fail at runtime.

Written after `ansible.builtin.script` was given a `stdin:` parameter it does
not accept. The role failed with "Unsupported parameters for ... script module:
stdin" — on the live host, mid-apply, after eleven tasks had already run.

Nothing caught it earlier, and that is the point of this file:

  ansible-playbook --syntax-check   parses YAML and playbook structure. Module
                                    arguments are validated by the module, at
                                    run time, on the target.
  ansible-lint (production profile)  passed clean. It checks style, naming,
                                    idioms and a fixed rule set — not whether a
                                    given module accepts a given key.

So a typo-level error in a parameter name survived every gate this repo had and
was found by a founder running the playbook. The same defect was present in
rollback.yml, which meant the recovery path was broken too: it would have failed
at the exact moment it was needed, after a bad apply, with the Gateway down.

That is the part worth guarding. A broken apply is visible immediately. A broken
rollback is invisible until it is the only thing standing between you and a dead
service.

Run: python3 tests/dc_module_args.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROLE = Path(__file__).resolve().parents[1] / "roles" / "dc-governed-config"

# Parameters each module does NOT accept, with the module that does. Deliberately
# small: this encodes mistakes actually made, not a reimplementation of Ansible's
# argument spec, which would rot and give false confidence.
FORBIDDEN = {
    "ansible.builtin.script": {
        "stdin": "command/shell accept stdin; script does not — stage a file and pass its path",
        "stdin_add_newline": "same as stdin",
        "warn": "removed from Ansible core",
    },
    "ansible.builtin.copy": {
        "stdin": "copy has no stdin; use content:",
    },
}


def parse_tasks(text: str) -> list[tuple[int, str, list[str]]]:
    """Return (line_no, module, keys) for each task, without a YAML library.

    Hand-rolled because this must run before and independently of any parsing
    that might itself be misconfigured, and because PyYAML would flatten the
    `args:` block into the same mapping as the module's own keys — losing the
    distinction that made the original bug possible to write.
    """
    tasks: list[tuple[int, str, list[str]]] = []
    current: tuple[int, str] | None = None
    keys: list[str] = []

    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())

        # A new task starts at list level.
        if stripped.startswith("- name:") and indent <= 2:
            if current:
                tasks.append((current[0], current[1], keys))
            current, keys = None, []
            continue

        if not stripped or stripped.startswith("#"):
            continue

        # `ansible.builtin.x:` at task level names the module.
        if stripped.endswith(":") and stripped.count(":") == 1:
            name = stripped[:-1]
            if name.startswith("ansible.builtin.") and indent == 2:
                current = (number, name)
                keys = []
                continue

        # Any `key:` nested under the module or under a sibling `args:` block.
        if current and indent >= 4 and ":" in stripped and not stripped.startswith("-"):
            keys.append(stripped.split(":", 1)[0].strip())

    if current:
        tasks.append((current[0], current[1], keys))
    return tasks


def main() -> int:
    problems: list[str] = []
    checked = 0

    for path in sorted((ROLE / "tasks").glob("*.yml")):
        for line_no, module, keys in parse_tasks(path.read_text()):
            checked += 1
            for bad, reason in FORBIDDEN.get(module, {}).items():
                if bad in keys:
                    problems.append(
                        f"{path.name}:{line_no}  {module} given '{bad}' — {reason}"
                    )

    for problem in problems:
        print(f"  FAIL  {problem}")

    if problems:
        print(f"\n{len(problems)} unsupported module parameter(s).")
        print("These fail at run time on the target, not at syntax-check.")
        return 1

    print(f"  PASS  no unsupported module parameters ({checked} module blocks checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
