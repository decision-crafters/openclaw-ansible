#!/usr/bin/env python3
"""Validate and CONSUME a model-override grant.

    validate_model_grant.py <grant.json> <schema.json> <agent-id> \
                            <governing-task-id> <ledger.json>

Exit 0 only if the grant is well formed, names this exact agent, is bound to
the task governing this invocation, and has never been used before. Every
violation is reported together: a validator that stops at the first one turns
one fix into several round trips.

WHY THIS EXISTS

`openclaw agent --model <id>` overrides an agent's pinned model at the CALL
SITE. It lives in the CLI, not in openclaw.json, so no amount of configuration
auditing can see it, and a governed harness that passes it silently runs an
agent the admission never examined. Until now the harnesses avoided it by
COMMENT, which is a convention, not a control.

FAIL-CLOSED

Absence of a grant is denial -- the gate emits no --model at all. The schema
then makes several over-broad grants NOT REPRESENTABLE AS A VALID GRANT:
`acceptedBy` is a const so a self-accepted grant does not validate, `singleUse`
is a const so a standing override does not validate, and `model` rejects
wildcards so a grant must name what will actually run.

That phrasing matters and an earlier version of this file overstated it. Those
constraints do not make the JSON inexpressible -- anyone can write the bytes.
They make it not representable as a VALID grant, which is a claim about
validation, not about what can be written.

TWO THINGS THE SCHEMA CANNOT DO, HANDLED HERE

`singleUse: true` was DECLARATIVE: the schema required the field and nothing
consumed the grant, so the same file could be presented again indefinitely. A
single-use grant that is never used up is a standing grant with a label.
Replay prevention is therefore behavioural: the grant's content digest is
recorded in a ledger on accept, and a digest already present is refused.

`taskId` was likewise DECLARATIVE: the pattern proved it LOOKED like a task id
and nothing compared it to the task actually governing the invocation. A grant
was task-LABELLED, not task-BOUND. It is now cross-checked against the
governing task passed by the caller, and a run with no governing task is
refused rather than treated as universally authorised.
"""
import hashlib
import json
import os
import sys
import time


def fail(errors):
    print("MODEL OVERRIDE GRANT REJECTED", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    print("\nNo --model will be passed. Absence of a valid grant is DENIAL,",
          file=sys.stderr)
    print("not an error to work around.", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 6:
        fail(["usage: validate_model_grant.py <grant.json> <schema.json> "
              "<agent-id> <governing-task-id> <ledger.json>"])
    grant_path, schema_path, agent_id, governing_task, ledger_path = sys.argv[1:6]

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
                f"the disallowed form does not validate — a claim about validation, not about what can be written")
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

    # --- cross-checks the schema cannot make ------------------------------
    if grant.get("agentId") and grant["agentId"] != agent_id:
        errors.append(
            f"grant names agent {grant['agentId']!r} but this run is for {agent_id!r}. "
            f"A grant for one agent does not authorise another.")

    # TASK BINDING. Without a governing task there is nothing to bind to, and a
    # grant that binds to nothing authorises everything.
    if not governing_task or governing_task.strip() in ("", "None"):
        errors.append(
            "no governing task was supplied for this invocation, so the grant's "
            "taskId cannot be checked against anything. A grant that binds to "
            "nothing is a standing grant. Set the governing task.")
    elif grant.get("taskId") and grant["taskId"] != governing_task:
        errors.append(
            f"grant is bound to {grant['taskId']!r} but this invocation is governed "
            f"by {governing_task!r}. A grant for one task does not authorise another.")

    # REPLAY. Digest the grant CONTENT, not its path: renaming or copying the
    # file must not mint a fresh use.
    raw = open(grant_path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    ledger = []
    if os.path.exists(ledger_path):
        try:
            ledger = json.load(open(ledger_path))
        except Exception as exc:
            fail([f"ledger unreadable ({exc}). Refusing rather than assuming the "
                  f"grant is unused — an unreadable ledger cannot show a replay."])
    if any(e.get("digest") == digest for e in ledger):
        prior = next(e for e in ledger if e["digest"] == digest)
        errors.append(
            f"this grant has already been used (digest {digest[:16]}…, consumed "
            f"{prior.get('usedAt')} for agent {prior.get('agentId')}). singleUse is "
            f"behavioural, not decorative: issue a new grant.")

    if errors:
        fail(errors)

    # Consume it. Recorded BEFORE returning success, so a crash after this point
    # cannot leave a used grant looking fresh.
    ledger.append({
        "digest": digest,
        "agentId": grant["agentId"],
        "model": grant["model"],
        "taskId": grant["taskId"],
        "usedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    tmp = ledger_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(ledger, fh, indent=2)
    os.replace(tmp, ledger_path)
    os.chmod(ledger_path, 0o600)

    print(f"GRANT ACCEPTED AND CONSUMED | agent={grant['agentId']} "
          f"model={grant['model']} task={grant['taskId']} "
          f"digest={digest[:16]}… — this grant is now spent")
    print(grant["model"])
    sys.exit(0)


if __name__ == "__main__":
    main()
