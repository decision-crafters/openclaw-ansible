#!/usr/bin/env python3
"""Choose the newest backup that OpenClaw would actually accept.

Usage: select_backup.py <backup-dir>   # schema on stdin

Replaces "restore the most recent backup", which failed on 2026-08-15 in three
separate ways at once:

  1. Most recent is not known-good. Play 2 ran twice, so the second backup
     captured a config that already contained the bad key. Restoring it restored
     the outage.

  2. mtime does not order the backups. Ansible's `copy` with `remote_src`
     preserves the source mtime, so four backups shared a timestamp of 18:47 and
     `sort | last` picked arbitrarily among ties. The previous version chose
     mtime over the filenames *specifically*, with a comment arguing mtime was
     "the fact we actually mean". The filenames carry timestamps this role
     generates itself and are the only accurate ordering available.

  3. Nothing checked whether a candidate was loadable before restoring it.

So: order by the timestamp in the filename, then walk newest-first and return
the first candidate whose governed keys satisfy OpenClaw's schema. Only the keys
this role writes are checked -- a full-config check would fail on plugin and
channel keys the schema does not model, and those are not ours to judge.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

# Exactly the paths dc-governed-config writes. A backup is rejected only for
# damage this role could have caused.
GOVERNED_PATHS = [
    ("gateway", "bind"),
    ("agents", "defaults", "sandbox", "mode"),
    ("agents", "defaults", "sandbox", "scope"),
    ("agents", "defaults", "sandbox", "workspaceAccess"),
    ("tools", "exec", "mode"),
]

# Schema-validity is not the only way a backup can be bad, and this is the
# second kind.
#
# `plugins.deny: ["slack"]` is legal config. It satisfies the schema, so the
# check above would pass it, and it would be selected as known-good — restoring
# a Gateway that is bound to loopback with no channel reaching it. Healthy by
# every measure this script had, and unreachable.
#
# That is structurally the same failure as 2026-08-15, when the newest backup
# was selected because nothing asked whether it was GOOD, only whether it was
# RECENT. Adding schema-validity narrowed "good" without finishing the job:
# valid and safe are still different questions.
#
# Founder decision 2026-08-15: Slack is the operator's only route to this
# Gateway until Tailscale exists. A backup that removes it is not a restore
# point, whatever the schema says about it.
FORBIDDEN_LIST_MEMBERS = {
    ("plugins", "deny"): ["slack", "ollama"],
}

STAMP = re.compile(r"(\d{8}T\d{6})")


def deref(node: dict, defs: dict, depth: int = 0) -> dict:
    while isinstance(node, dict) and "$ref" in node and depth < 30:
        node = defs.get(node["$ref"].split("/")[-1], {})
        depth += 1
    return node or {}


def enum_at(schema: dict, defs: dict, path: tuple[str, ...]) -> list | None:
    node = deref(schema, defs)
    for part in path:
        node = deref((node.get("properties") or {}).get(part, {}), defs)
        if not node:
            return None
    if "enum" in node:
        return list(node["enum"])
    vals: list = []
    for branch in (node.get("anyOf") or node.get("oneOf") or []):
        branch = deref(branch, defs)
        vals.extend(branch.get("enum", []))
        if "const" in branch:
            vals.append(branch["const"])
    return vals or None


def value_at(config: dict, path: tuple[str, ...]):
    node = config
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def sort_key(path: Path) -> str:
    """Order by the timestamp in the name. mtime is unusable -- see the docstring."""
    found = STAMP.search(path.name)
    return found.group(1) if found else ""


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: select_backup.py <backup-dir>  (schema on stdin)", file=sys.stderr)
        return 2

    schema_raw = sys.stdin.read()
    if not schema_raw.strip():
        print("no schema on stdin; refusing to call any backup good unchecked", file=sys.stderr)
        return 2
    schema = json.loads(schema_raw)
    defs = schema.get("$defs") or schema.get("definitions") or {}
    enums = {p: enum_at(schema, defs, p) for p in GOVERNED_PATHS}

    # Valid JSON of the wrong shape resolves no enums, which makes every check
    # below vacuous and every backup "acceptable" — this script's own version of
    # passing by asking nothing. Caught in testing on 2026-08-15 by piping the
    # committed fixture in place of the schema: it selected a backup that
    # severed operator access and exited 0.
    #
    # Every other guard in this role fails closed. This one failed open, which
    # is worse than absent: it reports a validated selection it never made.
    resolved = [p for p, values in enums.items() if values]
    if not resolved:
        print(
            "stdin parsed as JSON but resolved none of the governed enums "
            f"({', '.join('.'.join(p) for p in GOVERNED_PATHS)}). This is not "
            "OpenClaw's config schema — check that `openclaw config schema` "
            "output was piped in, not a fixture or an error page. Refusing "
            "rather than validating every backup against nothing.",
            file=sys.stderr,
        )
        return 2

    backups = sorted(Path(sys.argv[1]).glob("openclaw.json.*"), key=sort_key, reverse=True)
    if not backups:
        print("no backups found", file=sys.stderr)
        return 1

    rejected: list[str] = []
    for candidate in backups:
        try:
            config = json.loads(candidate.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            rejected.append(f"{candidate.name}: unreadable or not JSON ({exc.__class__.__name__})")
            continue

        problems = []
        for path, allowed in enums.items():
            value = value_at(config, path)
            if value is None or allowed is None:
                continue
            if value not in allowed:
                problems.append(f"{'.'.join(path)}={value!r} not in {allowed}")

        # Legal but unrecoverable. Checked separately from the schema because
        # the schema has nothing to say about it.
        for path, forbidden in FORBIDDEN_LIST_MEMBERS.items():
            value = value_at(config, path)
            if not isinstance(value, list):
                continue
            severed = [entry for entry in forbidden if entry in value]
            if severed:
                problems.append(
                    f"{'.'.join(path)} denies {severed}, which would restore a "
                    "runtime the operator cannot reach"
                )

        if problems:
            rejected.append(f"{candidate.name}: {'; '.join(problems)}")
            continue

        # Report the rejects too. A silent skip would hide that the newest
        # backups were poisoned, which is the fact worth knowing.
        for line in rejected:
            print(f"rejected {line}", file=sys.stderr)
        print(str(candidate))
        return 0

    for line in rejected:
        print(f"rejected {line}", file=sys.stderr)
    print("no backup satisfies the schema on the governed keys", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
