#!/usr/bin/env python3
"""Regenerate files/schema-keys.json from a raw `openclaw config schema` dump.

Usage: distill_schema_keys.py <raw-schema.json> --version <build> [--paths a,b,c] [--out <file>]

The fixture lets CI check that every value the governance overlay writes is LEGAL
under OpenClaw's own schema without OpenClaw installed (tests/dc_merge_contract.py
schema_floors). It is stamped with the build it was distilled from and says
"Regenerate after an OpenClaw upgrade" — this script is that regeneration, so the
fixture tracks the runtime instead of quietly describing a build that is gone.

Only the paths the role writes are kept (default: the paths already in the current
fixture, or --paths). For each: exists, enum (or null), type (or null). Reuses the
$ref resolver from schema_surface.py so both tools read the schema the same way.
Writes JSON with sorted keys, two-space indent, trailing newline — byte-stable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema_surface import resolve  # noqa: E402

DEFAULT_PATHS = [
    "agents.defaults.sandbox.docker.network", "agents.defaults.sandbox.mode",
    "agents.defaults.sandbox.scope", "agents.defaults.sandbox.workspaceAccess",
    "gateway.bind", "gateway.customBindHost", "gateway.port", "plugins.allow", "plugins.deny",
    "tools.allow", "tools.deny", "tools.elevated.enabled", "tools.exec.mode",
]


def _children(node: Any, root: Any) -> list[Any]:
    """Every node a property lookup may continue through: properties, combinators, items."""
    node = resolve(node, root)
    if not isinstance(node, dict):
        return []
    out = [node]
    for comb in ("anyOf", "oneOf", "allOf"):
        members = node.get(comb)
        if isinstance(members, list):
            for m in members:
                out += _children(m, root)
    items = node.get("items")
    if isinstance(items, dict):
        out += _children(items, root)
    return out


def lookup(root: Any, dotted: str) -> dict[str, Any] | None:
    nodes = [root]
    for seg in dotted.split("."):
        nxt: list[Any] = []
        for n in nodes:
            for cand in _children(n, root):
                props = cand.get("properties") if isinstance(cand, dict) else None
                if isinstance(props, dict) and seg in props:
                    nxt.append(resolve(props[seg], root))
        if not nxt:
            return None
        nodes = nxt
    node = nodes[0]
    enum = None
    t = None
    for cand in _children(node, root):
        if isinstance(cand, dict):
            if isinstance(cand.get("enum"), list) and enum is None:
                enum = list(cand["enum"])
            if "const" in cand:
                enum = (enum or []) + [cand["const"]]
            if t is None and isinstance(cand.get("type"), str):
                t = cand["type"]
    return {"enum": enum, "exists": True, "type": t}


def main(argv: list[str]) -> int:
    if len(argv) < 2 or "--version" not in argv:
        print(__doc__)
        return 2
    raw = Path(argv[1])
    version = argv[argv.index("--version") + 1]
    paths = DEFAULT_PATHS
    if "--paths" in argv:
        paths = [p for p in argv[argv.index("--paths") + 1].split(",") if p]
    out_path = Path(argv[argv.index("--out") + 1]) if "--out" in argv else None
    try:
        root = json.loads(raw.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"unreadable schema: {exc}")
        return 2
    result: dict[str, Any] = {}
    missing: list[str] = []
    for p in paths:
        spec = lookup(root, p)
        if spec is None:
            result[p] = {"enum": None, "exists": False, "type": None}
            missing.append(p)
        else:
            result[p] = spec
    fixture = {
        "_captured": __import__("datetime").date.today().isoformat(),
        "_comment": (f"Distilled from `openclaw config schema`, OpenClaw {version}. Only the paths "
                     "dc-governed-config writes. Regenerate after an OpenClaw upgrade with "
                     "files/distill_schema_keys.py; the full schema is ~2MB and is not committed."),
        "_openclaw_version": version,
        "_source": "openclaw config schema",
        "paths": dict(sorted(result.items())),
    }
    text = json.dumps(fixture, indent=2, sort_keys=True) + "\n"
    if out_path:
        out_path.write_text(text, encoding="utf-8")
        print(f"wrote {out_path} ({len(result)} paths, {len(missing)} missing: {missing})")
    else:
        sys.stdout.write(text)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
