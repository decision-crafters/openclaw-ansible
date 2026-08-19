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

That check must be ATOMIC ACROSS THE WHOLE TRANSACTION, not just at the write.
`os.replace()` makes the final replacement atomic and does nothing for the
read -> check -> append that precedes it: two concurrent validations can both
read the ledger before either records, and both conclude the grant is unused.
`singleUse` would then be at-most-once only when runs happen to be sequential.
An exclusive lock is held across the entire critical section, and a lock that
cannot be acquired REFUSES rather than proceeding unlocked.

`taskId` was likewise DECLARATIVE: the pattern proved it LOOKED like a task id
and nothing compared it to the task actually governing the invocation. A grant
was task-LABELLED, not task-BOUND. It is now cross-checked against the
governing task passed by the caller, and a run with no governing task is
refused rather than treated as universally authorised.
"""
import errno
import fcntl
import hashlib
import json
import os
import sys
import time


LOCK_TIMEOUT_S = 30

# Fault-injection hook, off by default. Widens the read -> check -> append
# window so a concurrency test can actually observe the race this lock exists
# to close.
#
# Without it the window is unobservable from a test: Python process startup
# dominates the critical section, so concurrent subprocesses never overlap
# inside it and the test passes IDENTICALLY with and without the lock. That is
# a control which cannot fail, which is worse than no control.
#
# Safe in production by placement: the delay is taken INSIDE the lock, so the
# worst it can do is make a run slower. It cannot widen a window that is held
# exclusively.
TEST_DELAY_MS = int(os.environ.get("DC_GRANT_TEST_DELAY_MS", "0") or "0")


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

    # Anything found so far is fatal before the ledger is touched. Failing here
    # avoids consuming a grant that was never going to be accepted.
    if errors:
        fail(errors)

    # REPLAY. Digest the grant CONTENT, not its path: renaming or copying the
    # file must not mint a fresh use.
    raw = open(grant_path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()

    # THE WHOLE read -> check -> append -> replace IS THE CRITICAL SECTION.
    # Holding a lock only over the write would leave the window this exists to
    # close: two validations reading before either records.
    lock_path = ledger_path + ".lock"
    deadline = time.time() + LOCK_TIMEOUT_S
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    fail([f"ledger lock error: {exc}"])
                if time.time() >= deadline:
                    # Refuse rather than proceed unlocked. A timeout means
                    # another validation holds the ledger; assuming the grant is
                    # unused is exactly the race being prevented.
                    fail([f"could not acquire the ledger lock within "
                          f"{LOCK_TIMEOUT_S}s ({lock_path}). Another validation "
                          f"holds it. Refusing rather than proceeding unlocked."])
                time.sleep(0.05)

        ledger = []
        if os.path.exists(ledger_path):
            try:
                ledger = json.load(open(ledger_path))
            except Exception as exc:
                fail([f"ledger unreadable ({exc}). Refusing rather than assuming the "
                      f"grant is unused — an unreadable ledger cannot show a replay."])
        # Fault-injection point: between reading the ledger and recording the
        # digest. Zero unless a test asks for it.
        if TEST_DELAY_MS:
            time.sleep(TEST_DELAY_MS / 1000.0)

        if any(e.get("digest") == digest for e in ledger):
            prior = next(e for e in ledger if e["digest"] == digest)
            fail([f"this grant has already been used (digest {digest[:16]}…, consumed "
                  f"{prior.get('usedAt')} for agent {prior.get('agentId')}). singleUse "
                  f"is behavioural, not decorative: issue a new grant."])

        # Consume it. Recorded BEFORE returning success and while still holding
        # the lock, so a crash after this cannot leave a used grant looking fresh
        # and no concurrent validation can observe the pre-append state.
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
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, ledger_path)
        os.chmod(ledger_path, 0o600)
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)

    print(f"GRANT ACCEPTED AND CONSUMED | agent={grant['agentId']} "
          f"model={grant['model']} task={grant['taskId']} "
          f"digest={digest[:16]}… — this grant is now spent")
    print(grant["model"])
    sys.exit(0)


if __name__ == "__main__":
    main()
