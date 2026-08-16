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

WHAT THIS FILE CANNOT DO, stated because a pre-filter mistaken for an authority
is worse than no pre-filter.

Cross-field constraints are invisible to it. On 2026-08-16 the runtime rejected
a profile setting both `tools.exec.mode` and `tools.exec.security`:

    tools.exec.mode cannot be combined with tools.exec.security or tools.exec.ask

Both keys exist, both values are legal enum members, and this file passes that
profile — verified by feeding the rejected version back. The walk below descends
overlay and schema together key by key, testing existence and enum membership
per key. "These two are mutually exclusive" is a relationship BETWEEN keys, and
there is nowhere in that walk to put it.

So: this is a cheap early filter for invented keys and illegal values.
`openclaw config patch --dry-run` is the authority — it runs the runtime's own
validator, including cross-field rules that appear nowhere in the JSON Schema
and could not be enumerated from it. Where the two disagree, the runtime wins.
"""

from __future__ import annotations

import json
import re
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


def child_schema(key: str, schema: dict, defs: dict):
    """Schema for `key`, or None when the schema genuinely has no place for it.

    Three ways a key can be legitimate, and the first version only knew one:

      properties           a closed, named set — an unknown key here is invented
      patternProperties    keys matching a regex
      additionalProperties a free-form map; the value is the schema for entries,
                           or True for anything

    `channels.slack.channels` is the third kind. It is keyed by Slack channel ID
    (`C0123456789`, or `team:T...:channel:C...` on Enterprise Grid), so the
    schema cannot enumerate its keys and declares none. The first version read
    every one of those as an invented key and refused a correct config with
    "no such key in the schema. Available at this level: []" — the empty list
    being the tell that this node never had named properties to begin with.

    A false rejection is not a safe failure. It teaches the operator that the
    gate cries wolf, and the next real rejection gets argued with rather than
    read. Being precise matters in both directions.
    """
    props = schema.get("properties") or {}
    if key in props:
        return deref(props[key], defs)

    for pattern, subschema in (schema.get("patternProperties") or {}).items():
        try:
            if re.search(pattern, key):
                return deref(subschema, defs)
        except re.error:
            continue

    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        return deref(additional, defs)
    if additional is True:
        return {}

    # Nothing declared at this level at all — no properties, no patterns, no
    # additionalProperties. The schema describes no shape here, so there is
    # nothing to check the key against and no basis for calling it invalid.
    # This also covers the empty schema `{}`, which JSON Schema defines as
    # "anything", and which is what a free-form map's entries resolve to.
    #
    # The distinction that keeps this honest: a node that HAS a named property
    # set and does not list the key is still an error. That is the case which
    # catches an invented key, and it is untouched.
    if not props and not schema.get("patternProperties"):
        if schema.get("additionalProperties") is False:
            return None
        return {}

    return None


def walk(overlay, schema: dict, defs: dict, path: list[str], errors: list[str]) -> None:
    """Descend the overlay and the schema together, recording disagreements."""
    schema = deref(schema, defs)
    props = schema.get("properties") or {}

    for key, value in overlay.items():
        here = path + [key]
        dotted = ".".join(here)

        child = child_schema(key, schema, defs)
        if child is None:
            errors.append(
                f"{dotted}: no such key in the schema. "
                f"Available at this level: {sorted(props)[:12]}"
            )
            continue

        if isinstance(value, dict):
            walk(value, child, defs, here, errors)
            continue

        # Lists take two forms and the first version only handled one.
        #
        # Enum-constrained items are checked for membership; `tools.deny` is a
        # free-form array, so absence of an enum there is expected rather than
        # suspicious.
        #
        # Arrays of OBJECTS are descended. `agents.list` is one, and the first
        # version walked straight past it — reporting "overlay validated against
        # the live schema" for a per-agent entry containing an invented key and
        # an illegal enum value, because it never looked inside the array.
        #
        # That is this file's own failure mode arriving from a new direction: a
        # check that passes by asking nothing. It is worse than an absent check,
        # because the absent one does not print the word "validated".
        if isinstance(value, list):
            items_schema = deref(child.get("items", {}), defs)
            item_enum = allowed_values(items_schema, defs)
            if item_enum:
                for item in value:
                    if item not in item_enum:
                        errors.append(
                            f"{dotted}[]: {item!r} is not allowed. Allowed: {item_enum}"
                        )
                continue
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    walk(item, items_schema, defs, here + [f"[{index}]"], errors)
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
