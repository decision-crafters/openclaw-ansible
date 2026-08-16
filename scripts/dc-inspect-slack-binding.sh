#!/usr/bin/env bash
# Document the Slack binding envelope for TASK-217, without disclosing a secret.
#
# Founder decision 2026-08-15 made Slack REQUIRED for baseline human <-> OpenClaw
# communication: gateway.bind is loopback, Tailscale does not exist yet, so Slack
# is the only route from a phone to this runtime. That settles WHETHER. What is
# still unanswered is the envelope:
#
#   exact bot / app identity        who may address it
#   granted OAuth scopes            which conversations it can see
#   channel binding                 whether DMs and private channels are reachable
#   credential scope                how the binding is stopped or revoked
#
# Read-only. Reads config, asks Slack who this token belongs to, and asks systemd
# what the STOP path is. Writes nothing, restarts nothing, sends no message.
#
# Run as root on the OpenClaw host:
#     sudo bash scripts/dc-inspect-slack-binding.sh
#
# Output: /root/dc-slack-binding-<date>.txt, mode 0600, chowned to the operator.
#
# ---------------------------------------------------------------------------
# On secrets: this script sees tokens and must never emit one. Everything from
# the config passes through redact() before it is printed, and the Slack calls
# send the token in a header while printing only what Slack says back. Scopes
# come from a response header, not from the credential.
#
# Read the output before pasting it anywhere. `grep -iE 'xox|token|secret'` on
# the file should return only redaction markers.
# ---------------------------------------------------------------------------

set -uo pipefail

OPERATOR="${SUDO_USER:-tosin}"
OC_USER="${OC_USER:-openclaw}"
OC_HOME="${OC_HOME:-/home/openclaw}"
CONFIG="$OC_HOME/.openclaw/openclaw.json"
UNIT="${UNIT:-openclaw-gateway.service}"
STAMP="$(date +%Y%m%dT%H%M%S)"
OUT="/root/dc-slack-binding-$STAMP.txt"

exec > >(tee "$OUT") 2>&1

echo "DC SLACK BINDING INVENTORY — TASK-217"
echo "host=$(hostname)  retrieved=$(date -Is)  config=$CONFIG"
echo "read-only: no config written, no restart, no message sent"
echo

# --- 1. What the config says the binding is ---------------------------------
# Redaction is by VALUE SHAPE, not by key name. A key-name denylist misses the
# key someone named differently; anything token-shaped goes regardless of where
# it sits.
echo "=== 1. Slack configuration (redacted) ======================================"
if [ ! -r "$CONFIG" ]; then
  echo "  UNREADABLE: $CONFIG — cannot report the binding. Everything below that"
  echo "  depends on it is UNKNOWN, not absent."
else
  python3 - "$CONFIG" <<'PY'
import json, re, sys

RAW = open(sys.argv[1]).read()
try:
    CONF = json.loads(RAW)
except json.JSONDecodeError as exc:
    # OpenClaw reads JSON5; strict parsing can fail on a hand-edited file.
    print(f"  config did not parse as strict JSON ({exc}).")
    print("  OpenClaw accepts JSON5, so this may be a comment or trailing comma")
    print("  rather than damage. Inspect by hand; do not treat as 'no Slack config'.")
    raise SystemExit(0)

# Anything that looks like a credential, whatever it is called.
SHAPES = [
    re.compile(r"^xox[abposr]-", re.I),      # Slack bot/app/user tokens
    re.compile(r"^[A-Za-z0-9_\-]{32,}$"),    # generic long opaque string
]

def redact(value):
    if not isinstance(value, str) or not value:
        return value
    for shape in SHAPES:
        if shape.search(value):
            return f"<REDACTED len={len(value)} prefix={value[:4]}...>"
    return value

def walk(node):
    if isinstance(node, dict):
        return {k: walk(v) for k, v in node.items()}
    if isinstance(node, list):
        return [walk(v) for v in node]
    return redact(node)

# Slack config location is not assumed — searched for, and reported wherever it
# turns up. Guessing `channels.slack` and printing nothing when it lives under
# `plugins.entries.slack` would read as "no Slack binding configured".
found = False
for top in ("channels", "plugins", "integrations", "connectors"):
    section = CONF.get(top)
    if not isinstance(section, (dict, list)):
        continue
    blob = json.dumps(section)
    if "slack" in blob.lower():
        found = True
        print(f"  --- {top} ---")
        print(json.dumps(walk(section), indent=2)[:6000])

if not found:
    print("  No 'slack' key under channels/plugins/integrations/connectors.")
    print("  Slack may be configured by environment variable instead — see 2b.")
    print("  Do NOT read this as 'Slack is not connected'; the founder confirmed")
    print("  working Slack communication on 2026-08-15.")

print()
print("  --- plugin policy as written ---")
plug = CONF.get("plugins", {})
print(f"  plugins.allow = {plug.get('allow', '<unset>')}")
print(f"  plugins.deny  = {plug.get('deny', '<unset>')}")
print(f"  plugins.enabled = {plug.get('enabled', '<unset>')}")
print(f"  plugins.bundledDiscovery = {plug.get('bundledDiscovery', '<unset>')}")
print(f"  gateway.bind = {CONF.get('gateway', {}).get('bind', '<unset>')}")
PY
fi
echo

# --- 1b. The founder's baseline requirements, scored against the config -----
# Section 1 prints what is configured. This asks the different question: of the
# nine elements the founder listed for "baseline Slack", which are actually
# present? Printing config and leaving the reader to notice an ABSENT key is how
# a missing control gets read as a satisfied one.
echo "=== 1b. Baseline requirements — present or absent ==========================="
if [ -r "$CONFIG" ]; then
  python3 - "$CONFIG" <<'PY'
import json, sys
try:
    conf = json.load(open(sys.argv[1]))
except Exception:
    print("  config unparseable — every row below is UNKNOWN, not absent.")
    raise SystemExit(0)

slack = (conf.get("channels") or {}).get("slack") or {}
if not slack:
    print("  No channels.slack section. Rows below are UNKNOWN.")
    raise SystemExit(0)

# Key names are guessed across plausible spellings on purpose. A miss must read
# as "not found under the names checked", never as "no restriction exists".
def first_present(*names):
    for n in names:
        if n in slack and slack[n] not in (None, "", [], {}):
            return n, slack[n]
    return None, None

rows = []

k, v = first_present("allowedUsers", "allowUsers", "permittedUsers",
                     "users", "allowlist", "allowFrom")
rows.append(("named permitted human sender(s)", k, v,
             "ANY workspace user who can reach the bot can drive it"))

k, v = first_present("channels", "allowedChannels", "channelAllowlist",
                     "conversations")
rows.append(("bounded channel/conversation scope", k, v,
             "no channel allowlist in config"))

k, v = first_present("groupPolicy")
rows.append(("group policy", k, v,
             "unset — behaviour is whatever the default is"))

k, v = first_present("dm", "allowDM", "dmPolicy", "directMessages")
rows.append(("DM reachability stated", k, v, "not stated in config"))

k, v = first_present("dedup", "deduplication", "loopProtection", "ignoreBots")
rows.append(("loop/dedup protection", k, v,
             "not configured here; may be internal to the connector"))

for label, key, value, absent_note in rows:
    if key:
        print(f"  PRESENT  {label}: {key} = {json.dumps(value)}")
    else:
        print(f"  ABSENT   {label} — {absent_note}")

print()
print("  Full channels.slack key list (names only, for anything missed above):")
print("   ", sorted(slack.keys()))
caps = slack.get("capabilities")
if isinstance(caps, dict):
    print("  capabilities:", json.dumps(caps))
PY
else
  echo "  config unreadable — UNKNOWN."
fi
echo

# The enum is the honest answer to "is 'open' as broad as it sounds". Reading the
# value and inferring from the word would be exactly the mistake that put an IP
# address into gateway.bind, which is also an enum.
# The whole channels.slack subtree, not just groupPolicy.
#
# The first version printed groupPolicy's enum and stopped, which answered "how
# broad is 'open'" (three values: open, disabled, allowlist) and left the
# question that actually matters unanswered: **where does the allowlist live?**
#
# `groupPolicy: "allowlist"` names a policy. It does not say which key holds the
# permitted entries, whether those entries are channel IDs or user IDs, or
# whether DMs fall under "group" at all — the name suggests group conversations,
# so direct messages may be governed by a different key or not gated here.
#
# Setting the policy without knowing where the list lives risks an allowlist that
# is empty by omission, which denies everything. That is the `plugins.allow: []`
# trap in a different key, and the founder reaches this Gateway from a phone
# through Slack — so the failure mode is losing access to the runtime, silently.
#
# Reading every key beats inferring from one. Descriptions are printed in full
# because the enum told us less than the wording will.
echo "  --- channels.slack schema subtree (from the live schema) ---"
OC_ENTRY="$(awk -F' ' '/^ExecStart=/ {for (i=1; i<=NF; i++) if ($i ~ /index\.js$/) {print $i; exit}}' \
  "$OC_HOME/.config/systemd/user/$UNIT" 2>/dev/null)"
if [ -n "${OC_ENTRY:-}" ]; then
  SCHEMA_TMP="$(mktemp)"
  runuser -u "$OC_USER" -- timeout 30 /usr/bin/node "$OC_ENTRY" config schema \
    </dev/null >"$SCHEMA_TMP" 2>/dev/null
  python3 - "$SCHEMA_TMP" <<'PY'
import json, sys

try:
    schema = json.load(open(sys.argv[1]))
except Exception as exc:
    print(f"    could not read schema ({exc.__class__.__name__})")
    raise SystemExit

defs = schema.get("$defs") or schema.get("definitions") or {}


def deref(node, depth=0):
    while isinstance(node, dict) and "$ref" in node and depth < 30:
        node = defs.get(node["$ref"].split("/")[-1], {})
        depth += 1
    return node or {}


def enum_of(node):
    if "enum" in node:
        return list(node["enum"])
    values = []
    for branch in (node.get("anyOf") or node.get("oneOf") or []):
        branch = deref(branch)
        values.extend(branch.get("enum", []))
        if "const" in branch:
            values.append(branch["const"])
    return values or None


node = deref(schema)
for part in ("channels", "slack"):
    node = deref((node.get("properties") or {}).get(part, {}))
    if not node:
        print(f"    path stops at {part!r} — not in the schema")
        raise SystemExit

props = node.get("properties") or {}
if not props:
    print("    channels.slack has no declared properties (free-form object)")
    raise SystemExit


def describe(name, spec, indent="    "):
    spec = deref(spec)
    kind = spec.get("type") or ("enum" if enum_of(spec) else "?")
    line = f"{indent}{name}: {kind}"
    values = enum_of(spec)
    if values:
        line += f"  enum={values}"
    if "default" in spec:
        line += f"  default={spec['default']!r}"
    print(line)
    desc = spec.get("description")
    if desc:
        print(f"{indent}  ↳ {desc}")
    # One level down: this is where an allowlist's item type would be declared.
    if spec.get("type") == "array":
        items = deref(spec.get("items", {}))
        item_enum = enum_of(items)
        print(f"{indent}  items: {items.get('type') or '?'}"
              + (f"  enum={item_enum}" if item_enum else ""))
        if items.get("description"):
            print(f"{indent}    ↳ {items['description']}")
    for sub_name, sub_spec in sorted((spec.get("properties") or {}).items()):
        describe(sub_name, sub_spec, indent + "    ")


for name, spec in sorted(props.items()):
    describe(name, spec)

# Named explicitly because these are the keys the bounded posture needs and the
# ones most likely to be absent. "Not found" here is itself the finding: it
# means the control does not exist under the name we assumed, and the posture
# must be built from what IS declared above rather than from what we expected.
print()
print("    keys the bounded posture depends on:")
for wanted in ("groupPolicy", "allowedChannels", "channels", "allowlist",
               "allowedUsers", "users", "dm", "dmPolicy", "allowedTeams"):
    print(f"      {wanted}: {'PRESENT' if wanted in props else 'not declared'}")
PY
  rm -f "$SCHEMA_TMP"
else
  echo "    could not locate the OpenClaw entrypoint; schema not consulted"
fi
echo

# --- 2. Where the credential actually comes from ----------------------------
echo "=== 2. Credential source (names only, never values) ========================"
ENVFILE="$OC_HOME/.env"
if [ -r "$ENVFILE" ]; then
  echo "  $ENVFILE defines (names only):"
  # sed, not grep -P: the lookahead form is a PCRE construct and grep here is
  # ERE, so it would fail and fall through to printing nothing useful.
  sed -nE 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z0-9_]+)=.*/    \2/p' "$ENVFILE"
  echo "  mode=$(stat -c '%a %U:%G' "$ENVFILE")"
else
  echo "  $ENVFILE not readable or absent."
fi
echo "  2b. Slack-related variables in the unit environment (names only):"
systemctl --user -M "$OC_USER@" show "$UNIT" -p Environment 2>/dev/null \
  | tr ' ' '\n' | sed -nE 's/^(SLACK[A-Z0-9_]*)=.*/    \1 (value withheld)/p' \
  || echo "    could not read unit environment"
echo

# --- 3. Who this token actually is, according to Slack ----------------------
# The authoritative answer. The config says what was configured; Slack says what
# the credential resolves to, and those are different claims. auth.test is
# read-only and identity-only.
echo "=== 3. Slack identity and granted scopes ==================================="
# `export FOO=` is as common as `FOO=` in a .env that gets sourced, and missing
# it would report the token absent — an UNKNOWN that looks like a finding.
TOKEN="$(sed -nE 's/^[[:space:]]*(export[[:space:]]+)?SLACK_BOT_TOKEN=["'"'"']?([^"'"'"'[:space:]]+).*/\2/p' "$ENVFILE" 2>/dev/null | head -1)"

# The first run of this script on host `openclaw` (2026-08-15) reported identity
# and scopes UNKNOWN because it looked only in .env, which holds OLLAMA_API_KEY
# and nothing else. The Slack credentials are in the config, under
# `channels.slack.botToken` — a location section 1 had already printed, redacted,
# two screens above the "no token found" message.
#
# So the envelope's most important question went unanswered because the lookup
# and the discovery were written as if they were about different things. Falling
# back to the config is not a convenience; without it the script reports UNKNOWN
# for something it is holding.
if [ -z "${TOKEN:-}" ] && [ -r "$CONFIG" ]; then
  TOKEN="$(python3 - "$CONFIG" <<'PY'
import json, sys
try:
    conf = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(0)
# Both known homes. Slack registers twice on this host: credentials under
# `channels.slack`, an enablement flag under `plugins.entries.slack`.
for path in (("channels", "slack", "botToken"),
             ("plugins", "entries", "slack", "botToken"),
             ("channels", "slack", "token")):
    node = conf
    for part in path:
        if not isinstance(node, dict) or part not in node:
            node = None
            break
        node = node[part]
    if isinstance(node, str) and node.startswith("xox"):
        print(node)
        break
PY
)"
  [ -n "${TOKEN:-}" ] && echo "  token source: $CONFIG (channels.slack) — not .env"
fi

if [ -z "${TOKEN:-}" ]; then
  echo "  No bot token found in $ENVFILE or $CONFIG."
  echo "  Identity and scopes are UNKNOWN — this is the single most important"
  echo "  gap in the envelope, because scopes are what actually bound the app."
  echo "  If the token lives elsewhere, re-run with: SLACK_TOKEN=xoxb-... $0"
  TOKEN="${SLACK_TOKEN:-}"
fi
if [ -n "${TOKEN:-}" ]; then
  # -D dumps headers: X-OAuth-Scopes is where the granted scope list lives, and
  # it is the answer to "what can this app do", not the config.
  HDR="$(mktemp)"
  BODY="$(curl -s -D "$HDR" -X POST https://slack.com/api/auth.test \
            -H "Authorization: Bearer $TOKEN" 2>/dev/null)"
  echo "  auth.test (identity):"
  echo "$BODY" | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('    unparseable response'); raise SystemExit
if not d.get('ok'):
    print(f\"    NOT OK: {d.get('error')} — the credential is invalid or revoked.\")
else:
    for k in ('team','team_id','user','user_id','bot_id','url','is_enterprise_install'):
        if k in d: print(f'    {k} = {d[k]}')
"
  echo "  granted OAuth scopes (from response headers — the real permission set):"
  grep -i '^x-oauth-scopes:' "$HDR" | sed 's/^/    /' || echo "    header absent"
  grep -i '^x-accepted-oauth-scopes:' "$HDR" | sed 's/^/    /' || true
  rm -f "$HDR"
else
  echo "  Skipped — no token available. Record as UNKNOWN, not as 'no scopes'."
fi
echo

# --- 4. Which conversations it can actually see -----------------------------
echo "=== 4. Conversation reach =================================================="
if [ -n "${TOKEN:-}" ]; then
  echo "  Conversations this bot is a member of (its actual visibility,"
  echo "  which is narrower than its scopes and is the number that matters):"
  curl -s -X POST https://slack.com/api/users.conversations \
    -H "Authorization: Bearer $TOKEN" \
    -d "types=public_channel,private_channel,mpim,im&limit=200" 2>/dev/null \
  | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('    unparseable response'); raise SystemExit
if not d.get('ok'):
    print(f\"    NOT OK: {d.get('error')}\")
    print('    (missing scope here is itself a finding: it bounds the app)')
else:
    ch=d.get('channels',[])
    print(f'    {len(ch)} conversation(s):')
    for c in ch:
        kind='private' if c.get('is_private') else 'public'
        if c.get('is_im'): kind='DM'
        elif c.get('is_mpim'): kind='group-DM'
        print(f\"      {c.get('name', c.get('id'))}  [{kind}]  id={c.get('id')}\")
    if not ch:
        print('    none — the app is installed but joined to nothing.')
"
else
  echo "  Skipped — no token. UNKNOWN."
fi
echo

# --- 4b. Who is on the other end of each DM ---------------------------------
# The bounded posture must NAME the founder's DM and exclude the other, which
# is impossible while both are opaque IDs.
#
# This cannot be answered from the Claude Slack connector: its
# list_channel_members explicitly does not support DMs. The bot's own token can,
# via conversations.members, so the credential already being documented here is
# the only thing that can close the question.
#
# Participants only. conversations.history is NOT called and no message content
# is read — identifying who a conversation is with does not require reading what
# was said in it, and the second is a much larger intrusion than this task needs.
echo "=== 4b. DM participants (identity only, no message content) ================="
if [ -n "${TOKEN:-}" ]; then
  DM_IDS="$(curl -s -X POST https://slack.com/api/users.conversations \
    -H "Authorization: Bearer $TOKEN" -d "types=im&limit=200" 2>/dev/null \
    | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
if d.get('ok'):
    print(' '.join(c['id'] for c in d.get('channels',[])))
")"
  if [ -z "${DM_IDS:-}" ]; then
    echo "  No DMs returned, or the token lacks im:read. UNKNOWN — not 'no DMs'."
  fi
  for dm in ${DM_IDS:-}; do
    members="$(curl -s -X POST https://slack.com/api/conversations.members \
      -H "Authorization: Bearer $TOKEN" -d "channel=$dm&limit=50" 2>/dev/null \
      | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
print(' '.join(d.get('members',[])) if d.get('ok') else 'ERR:'+str(d.get('error')))
")"
    case "$members" in
      ERR:*) echo "  $dm -> could not list members (${members#ERR:})"; continue ;;
    esac
    names=""
    for uid in $members; do
      who="$(curl -s -X POST https://slack.com/api/users.info \
        -H "Authorization: Bearer $TOKEN" -d "user=$uid" 2>/dev/null \
        | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: raise SystemExit
if not d.get('ok'): print('?'); raise SystemExit
u=d['user']
tag='bot' if u.get('is_bot') else 'human'
print(f\"{u.get('name','?')}[{tag}]\")
")"
      names="$names ${uid}=${who:-?}"
    done
    echo "  $dm ->$names"
  done
  echo
  echo "  The founder's DM is the one containing U0EXAMPLE01 (tosin.akinosho)."
  echo "  That conversation MUST appear in dc_slack_required_conversations."
  echo "  Founder confirmed 2026-08-16 that the access path is channel AND DM,"
  echo "  device-dependent — so excluding DMs as a class would sever the phone"
  echo "  path this whole governance decision exists to protect."
else
  echo "  Skipped — no token. UNKNOWN."
fi
echo

# --- 5. The STOP path -------------------------------------------------------
# Required by TASK-217. A binding with no demonstrated revoke path is not
# bounded; it is merely undocumented.
echo "=== 5. STOP / revoke path =================================================="
echo "  Unit state:"
systemctl --user -M "$OC_USER@" is-active "$UNIT" 2>/dev/null | sed 's/^/    active=/' \
  || runuser -u "$OC_USER" -- env XDG_RUNTIME_DIR="/run/user/$(id -u "$OC_USER")" \
       systemctl --user is-active "$UNIT" 2>&1 | sed 's/^/    active=/'
cat <<'STOP'

  Three levers, in increasing order of severity. Each should be REHEARSED, not
  assumed — an untested stop path is a claim, not a control.

    1. Stop the runtime          (reversible, seconds, kills all channels)
         runuser -u openclaw -- env XDG_RUNTIME_DIR=/run/user/$(id -u openclaw) \
           systemctl --user stop openclaw-gateway.service

    2. Deny the plugin           (reversible, survives restart, Slack only)
         set dc_plugins_deny: [firecrawl, slack] and re-run the role
         NOTE: the role REFUSES this by design — slack is in dc_plugins_required.
         Removing it from that list is a deliberate governance act and should be
         recorded, which is the entire point of making it awkward.

    3. Revoke the credential     (NOT reversible from this host — Slack-side)
         Slack admin -> app -> OAuth & Permissions -> revoke, or rotate the
         token. This is the only lever that holds if the host is untrusted.

  Levers 1 and 2 stop OpenClaw from USING Slack. Only lever 3 stops the
  credential from working. If the question is "what if the host is compromised",
  1 and 2 are not answers.
STOP
echo

echo "=== end ===================================================================="
chown "$OPERATOR":"$OPERATOR" "$OUT" 2>/dev/null || true
chmod 600 "$OUT"
echo "written to $OUT (0600, owned by $OPERATOR)"
echo
echo "BEFORE SHARING: grep -iE 'xox|secret|password' \"$OUT\""
echo "Anything but redaction markers means stop and re-check."
