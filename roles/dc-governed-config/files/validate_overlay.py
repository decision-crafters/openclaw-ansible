#!/usr/bin/env python3
"""Check a governance overlay against OpenClaw's own config schema.

Usage: validate_overlay.py '<overlay-json>' <schema-path>
       validate_overlay.py '<overlay-json>'            # schema on stdin

The schema path exists because `ansible.builtin.script` has no `stdin`
parameter — that belongs to `command`/`shell`. The role passed one anyway and
failed at runtime with "Unsupported parameters", which neither
`ansible-playbook --syntax-check` nor `ansible-lint` catches: module arguments
are validated when the module runs, not when the playbook is parsed.

stdin is kept as a fallback so this stays usable by hand and from tests.

Exists because of a specific failure. Every assertion in this role verified that
values reached the merged config; none verified that OpenClaw would accept it.
`gateway.bind: "127.0.0.1"` satisfied all of them, then crash-looped the daemon
because `bind` is an enum — auto | lan | loopback | custom | tailnet — and not
an address.

The documentation review that followed was no better. It concluded `gateway.bind`
did not exist, and concluded the same about `tools.exec.mode`. The schema shows
both exist. Two wrong answers from prose, one right answer from asking the
program. So this reads the schema the runtime actually validates against.

Two failure classes are caught:

  invented key   — a path the schema has no property for
  invalid value  — a value outside the enum for a path that does exist

The second is the one that bit us, and the one a plain "does this key exist"
check would have missed.
"""

from __future__ import annotations

import json
import sys


def deref(node: dict, defs: dict, depth: int = 0) -> dict:
    """Follow $ref chains. Bounded, because a malformed schema should not hang."""
    while isinstance(node, dict) and "$ref" in node and depth < 30:
        node = defs.get(node["$ref"].split("/")[-1], {})
        depth += 1
    return node or {}


def allowed_values(node: dict, defs: dict) -> list | None:
    """Enum values for a node, including through anyOf/oneOf unions.

    Returns None when the node is not enum-constrained — which is not the same
    as "any value is fine", only that this check has nothing to say about it.
    """
    if "enum" in node:
        return list(node["enum"])
    values: list = []
    for branch in (node.get("anyOf") or node.get("oneOf") or []):
        branch = deref(branch, defs)
        if "enum" in branch:
            values.extend(branch["enum"])
        elif "const" in branch:
            values.append(branch["const"])
    return values or None


def walk(overlay, schema: dict, defs: dict, path: list[str], errors: list[str]) -> None:
    """Descend the overlay and the schema together, recording disagreements."""
    schema = deref(schema, defs)
    props = schema.get("properties") or {}

    for key, value in overlay.items():
        here = path + [key]
        dotted = ".".join(here)

        if key not in props:
            errors.append(
                f"{dotted}: no such key in the schema. "
                f"Available at this level: {sorted(props)[:12]}"
            )
            continue

        child = deref(props[key], defs)

        if isinstance(value, dict):
            walk(value, child, defs, here, errors)
            continue

        # Lists are checked for membership per item where the item type is
        # enum-constrained; tools.deny is a free-form array, so absence of an
        # enum here is expected rather than suspicious.
        if isinstance(value, list):
            item_enum = allowed_values(deref(child.get("items", {}), defs), defs)
            if item_enum:
                for item in value:
                    if item not in item_enum:
                        errors.append(
                            f"{dotted}[]: {item!r} is not allowed. Allowed: {item_enum}"
                        )
            continue

        enum = allowed_values(child, defs)
        if enum is not None and value not in enum:
            errors.append(
                f"{dotted}: {value!r} is not allowed. Allowed: {enum}. "
                "This is the class of error that took the Gateway down."
            )


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: validate_overlay.py '<overlay-json>' [schema-path]", file=sys.stderr)
        return 2

    try:
        overlay = json.loads(sys.argv[1])
    except json.JSONDecodeError as exc:
        print(f"overlay is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if len(sys.argv) > 2:
        try:
            with open(sys.argv[2]) as handle:
                raw = handle.read()
        except OSError as exc:
            print(f"cannot read schema at {sys.argv[2]}: {exc}", file=sys.stderr)
            return 2
    else:
        raw = sys.stdin.read()

    if not raw.strip():
        print("schema is empty; refusing to report a config valid unchecked", file=sys.stderr)
        return 2

    try:
        schema = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"schema is not valid JSON: {exc}", file=sys.stderr)
        return 2

    defs = schema.get("$defs") or schema.get("definitions") or {}
    errors: list[str] = []
    walk(overlay, schema, defs, [], errors)

    if errors:
        for error in errors:
            print(f"  {error}")
        print(f"\n{len(errors)} overlay key(s) rejected by OpenClaw's schema.")
        return 1

    checked = json.dumps(overlay)
    print(f"overlay validated against the live schema ({len(checked)} bytes of overlay)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
