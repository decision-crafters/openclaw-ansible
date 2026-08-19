# Decision Crafters governed configuration

This fork adds one role, `dc-governed-config`, and changes nothing upstream.

## Why it exists

`roles/openclaw` installs and hardens a host. It deliberately does not configure
OpenClaw or install its daemon, and says so in `roles/openclaw/tasks/openclaw.yml`:

```
# NOTE: We do NOT create config.yml here - openclaw onboard/configure will do that
# We also do NOT install the systemd service - openclaw onboard --install-daemon will do that
```

That is a reasonable upstream boundary — onboarding is interactive and
provider-specific. But it means the playbook alone produces a **hardened host
running an ungoverned OpenClaw**: sandbox off, tools unrestricted, gateway bound
whereever onboarding chose.

Decision Crafters requires those controls to be set and *evidenced*, so this
role supplies them.

## What it enforces

Read from `roles/dc-governed-config/defaults/main.yml`; every value is
overridable and every default is the restrictive one.

| Control | Value | Why |
| --- | --- | --- |
| `agents.defaults.sandbox.mode` | `all` | Sandboxes every agent, not only non-main ones |
| `agents.defaults.sandbox.workspaceAccess` | `ro` | Enough to read a frozen source packet, not to write one |
| `tools.deny` | 10 mutating tools | Deny always wins, so a tool added by a future release cannot arrive pre-permitted |
| `tools.allow` | `[]` | See below — this one is load-bearing |
| `tools.elevated.enabled` | `false` | Set independently of `exec` denial so neither relies on the other |
| `gateway.bind` | `127.0.0.1` | A firewall in front of a wildcard listener is defence in depth, not this control |

### Why `tools.allow` is cleared explicitly

OpenClaw documents that a non-empty `allow` blocks everything outside it. If
onboarding wrote an allow-list and this role only added a deny-list, the
effective policy would be **partly ours and partly onboarding's** — a policy
nobody declared and nobody reviewed.

Clearing `allow` deactivates the allow-list so the deny-list is the whole
policy. This was not designed in; it was found by `tests/dc_merge_contract.py`
on its first run, when the merge left a stale allow-list intact.

Narrow the profile by extending `deny`, never by populating `allow`.

## How it behaves

**It never creates the config.** `openclaw onboard` owns
`~/.openclaw/openclaw.json` and would overwrite anything staged beforehand,
leaving controls absent while appearing applied. If the file is missing, the
role fails with instructions rather than writing one.

**It merges, it does not replace.** Governance keys win; channel tokens, model
choices, agent entries and everything else onboarding wrote are preserved. Both
halves are asserted in the merge-contract test.

**It refuses a config it cannot parse.** OpenClaw reads JSON5, which permits
comments that strict JSON parsing rejects. A merge built on a failed parse would
silently drop every key it could not see, so an unparseable config is a stop.

**It backs up before writing**, timestamped, into `.openclaw/dc-backups/`, so
rollback is a file copy.

**It refuses to leave the running gateway diverged.** If the config is written
but the systemd unit cannot be found to restart, the role fails. A file showing
controls that are not loaded is more dangerous than one that was never written —
an operator reads it and is wrong.

## Order of operations

```bash
ansible-playbook playbooks/governed-lab.yml --tags install   # host hardening
# then, as the openclaw user, interactively:
openclaw onboard --install-daemon
ansible-playbook playbooks/governed-lab.yml --tags govern    # apply + verify
```

Running the playbook end to end in one pass stops at the second play with an
explanation. That is intended.

Set `dc_openclaw_service` to whatever unit onboarding installed.

## Evidence

`tasks/verify.yml` re-reads the config **from disk** — not from the value just
computed — and asserts each control, then emits a single
`DC-GOVERNED-CONFIG RECEIPT` line. Asserting against the computed value would
prove only that the computation was self-consistent; re-reading proves the
control reached the file.

These assertions are the receipts TASK-217 criteria 5, 6 and 7 require.

## The fork invariant

**This fork is additive. No upstream file is modified.**

`.github/workflows/dc-governed-config.yml` enforces it on every push:
`git diff --diff-filter=MD upstream/main...HEAD` must be empty, and
`roles/openclaw/` must be byte-identical to upstream.

That is why governance lives in a separate role rather than as edits to
`roles/openclaw`, and why our CI is a separate workflow file rather than an edit
to `lint.yml`. It keeps "we run stock upstream plus a governance layer"
verifiable in one command instead of a claim requiring an audit.

Upstream baseline pinned at `d01f655f443216d53d62a39ba2e7d7c7c425ddc0`. Pin the
commit, not the `v2.0.0` tag — the tag is 67 commits behind and predates the fix
that removes the service user from the root-equivalent `docker` group.

## Tests

```bash
python3 tests/dc_merge_contract.py
```

22 checks in two groups. **Contract** checks prove the merge overrides
permissive values and preserves everything else. **Floor** checks prove the
configured values are themselves safe — without them the suite would pass with
`dc_sandbox_mode: "off"`, since every contract check compares the result against
the role's own defaults.

## Provenance

Controls come from PRM-5 v0.4 (Notion, canonical). Change PRM-5 first, then
mirror it here. Authorised by TASK-217 under TASK-153.
