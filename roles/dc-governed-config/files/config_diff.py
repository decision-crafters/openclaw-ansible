#!/usr/bin/env python3
"""Report which dotted config paths changed between two JSON files, against an allowlist.

Usage: config_diff.py <before.json> <after.json> --allow <prefix,prefix,...>

Prints one changed path per line (list indices as `*`, so `agents.list.0.model.primary`
reads `agents.list.*.model.primary`). Exit codes follow schema_surface.py:

  0  no change, or every changed path is under an allowed prefix
  1  at least one changed path is OUTSIDE the allowlist (listed after `OUTSIDE:`)
  2  an input could not be read or parsed

Why this exists: `openclaw doctor --fix` is a third configuration-mutation path
(TASK-242) that rewrites whatever it decides needs migrating. The upgrade play may
let it run only when the migration triggers are present and only if everything it
changed is inside the expected key set. This is the check that makes "only" true.
"""
from __future__ import annotations

import json
import sys
from typing import Any


def _load(path: str) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def changed_paths(before: Any, after: Any, prefix: str = "") -> set[str]:
    if isinstance(before, dict) and isinstance(after, dict):
        out: set[str] = set()
        for key in set(before) | set(after):
            p = f"{prefix}.{key}" if prefix else key
            if key not in before or key not in after:
                out.add(p)
            else:
                out |= changed_paths(before[key], after[key], p)
        return out
    if isinstance(before, list) and isinstance(after, list):
        out = set()
        for i in range(max(len(before), len(after))):
            p = f"{prefix}.*" if prefix else "*"
            if i >= len(before) or i >= len(after):
                out.add(p)
            else:
                out |= changed_paths(before[i], after[i], p)
        return out
    return {prefix} if before != after else set()


def outside(paths: set[str], allow: list[str]) -> list[str]:
    def allowed(p: str) -> bool:
        return any(p == a or p.startswith(a + ".") for a in allow)
    return sorted(p for p in paths if not allowed(p))


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    allow: list[str] = []
    if "--allow" in argv:
        i = argv.index("--allow")
        if i + 1 < len(argv):
            allow = [a for a in argv[i + 1].split(",") if a]
    try:
        before, after = _load(argv[1]), _load(argv[2])
    except (OSError, json.JSONDecodeError) as exc:
        print(f"unreadable input: {exc}")
        return 2
    paths = changed_paths(before, after)
    for p in sorted(paths):
        print(f"CHANGED: {p}")
    bad = outside(paths, allow)
    if bad:
        print("OUTSIDE: " + ", ".join(bad))
        return 1
    print(f"changed={len(paths)} outside_allowlist=0")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
