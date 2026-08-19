#!/usr/bin/env python3
"""Validate a model-override grant against the schema and the run it claims.

    validate_model_grant.py <grant.json> <schema.json> <agent-id>

Exit 0 only if the grant is well formed AND names this exact agent. Every
violation is reported together: a validator that stops at the first one turns
one fix into several round trips.

WHY THIS EXISTS

`openclaw agent --model <id>` overrides an agent's pinned model at the CALL
SITE. It lives in the CLI, not in openclaw.json, so no amount of configuration
auditing can see it, and a governed harness that passes it silently runs an
agent the admission never examined. Until now the harnesses avoided it by
COMMENT, which is a convention, not a control.

FAIL-CLOSED BY CONSTRUCTION

Absence of a grant is denial -- the gate emits no --model at all. The schema
then makes several over-broad grants INEXPRESSIBLE rather than merely invalid:
`acceptedBy` is a const so a self-accepted grant cannot be written, `singleUse`
is a const so a standing override cannot be written, and `model` rejects
wildcards so a grant must name what will actually run.
"""
import json
import sys


def fail(errors):
    print("MODEL OVERRIDE GRANT REJECTED", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    print("\nNo --model will be passed. Absence of a valid grant is DENIAL,",
          file=sys.stderr)
    print("not an error to work around.", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        fail(["usage: validate_model_grant.py <grant.json> <schema.json> <agent-id>"])
    grant_path, schema_path, agent_id = sys.argv[1:4]

    errors = []
    try:
        grant = json.load(open(grant_path))
    except Exception as exc:
        fail([f"grant unreadable: {exc}"])
    try:
        schema = json.load(open(schema_path))
    except Exception as exc:
        fail([f"schema unreadable: {exc}"])

    props = schema["properties"]

    for field in schema["required"]:
        if field not in grant:
            errors.append(f"missing required field: {field}")

    for field in grant:
        if field not in props:
            errors.append(f"unknown field (additionalProperties is false): {field}")

    for field, spec in props.items():
        if field not in grant:
            continue
        value = grant[field]
        if "const" in spec and value != spec["const"]:
            errors.append(
                f"{field} must be {spec['const']!r}, got {value!r} — this is a const so "
                f"the disallowed form cannot be expressed, not merely rejected")
        if spec.get("type") == "string":
            if not isinstance(value, str):
                errors.append(f"{field} must be a string")
                continue
            if len(value) < spec.get("minLength", 0):
                errors.append(
                    f"{field} is {len(value)} chars, minimum {spec['minLength']}")
            import re
            if "pattern" in spec and not re.match(spec["pattern"], value):
                errors.append(f"{field}={value!r} does not match {spec['pattern']}")

    # The cross-check the schema cannot make: does this grant authorise THIS run?
    if grant.get("agentId") and grant["agentId"] != agent_id:
        errors.append(
            f"grant names agent {grant['agentId']!r} but this run is for {agent_id!r}. "
            f"A grant for one agent does not authorise another.")

    if errors:
        fail(errors)

    print(f"GRANT ACCEPTED | agent={grant['agentId']} model={grant['model']} "
          f"task={grant['taskId']} singleUse={grant['singleUse']}")
    print(grant["model"])
    sys.exit(0)


if __name__ == "__main__":
    main()
