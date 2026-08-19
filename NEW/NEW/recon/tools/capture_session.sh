#!/usr/bin/env bash
# capture_session.sh — fill ledger/cookies_session.json accounts A/B with REAL
# sessions for targets that have a public registration surface.
#
# Modes:
#   1. USER-PROVIDED email(s): --email-a/-b [--pass-a/-b] — the script uses your
#      existing mail.tm inbox to receive the target's confirmation/login mail and
#      can log into the target with the supplied credentials. Your password is
#      never written to any file; it is only sent to the target's login form.
#   2. AUTO-CREATE (default): fresh account_a@mail.tm / account_b@mail.tm inboxes
#      created on the fly via the mail.tm API.
#
# What this script CAN do (target-agnostic):
#   - Create (or reuse) mail.tm inboxes A and B
#   - Wait for the target's mail, print the confirmation link / credentials
#   - Log into the target with a generic form and capture the session cookie
#
# What you must do (target-specific, cannot be automated):
#   - Open the printed confirmation link and complete signup on the TARGET,
#     or confirm the login URL + field names (or log in in a browser and paste
#     the session cookie)
#
# Usage:
#   ./capture_session.sh <target> [--email-a a@mail.tm] [--pass-a pw] \
#       [--email-b b@mail.tm] [--pass-b pw] \
#       [--login-url URL] [--user-field NAME] [--pass-field NAME]
#
# Then paste the printed session cookie into ledger/cookies_session.json
# (label A / B) and set status: "filled".
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "usage: $0 <target> [--email-a ADDR] [--pass-a PW] [--email-b ADDR] [--pass-b PW] [--login-url URL] [--user-field NAME] [--pass-field NAME]"
  exit 1
fi
TARGET="${TARGET#https://}"; TARGET="${TARGET%%/*}"

# --- parse args ---
EMAIL_A=""; PASS_A=""; EMAIL_B=""; PASS_B=""
LOGIN_URL=""; U_FIELD="email"; P_FIELD="password"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --email-a) EMAIL_A="$2"; shift 2;;
    --pass-a)  PASS_A="$2"; shift 2;;
    --email-b) EMAIL_B="$2"; shift 2;;
    --pass-b)  PASS_B="$2"; shift 2;;
    --login-url) LOGIN_URL="$2"; shift 2;;
    --user-field) U_FIELD="$2"; shift 2;;
    --pass-field) P_FIELD="$2"; shift 2;;
    *) shift;;
  esac
done

# defaults when not provided
EMAIL_A="${EMAIL_A:-account_a@mail.tm}"
EMAIL_B="${EMAIL_B:-account_b@mail.tm}"
GEN_PW_A="Hunt-A-$(date +%s)"; GEN_PW_B="Hunt-B-$(date +%s)"
PASS_A="${PASS_A:-$GEN_PW_A}"   # if user gave --pass-a, it stays; else generated
PASS_B="${PASS_B:-$GEN_PW_B}"

API="https://api.mail.tm"
JAR_A="/tmp/mailtm_a.json"; JAR_B="/tmp/mailtm_b.json"

# --- mailbox setup: use existing or create ---
setup_mailbox() {
  local label="$1" addr="$2" pw="$3" jar="$4"
  local existed=0
  if curl -fsS "$API/accounts" -o /dev/null; then :; fi
  # does the account exist? try login first (covers user-provided accounts)
  if token=$(curl -fsS -X POST "$API/token" -H "Content-Type: application/json" \
      -d "{\"address\":\"$addr\",\"password\":\"$pw\"}" \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null) && [[ -n "$token" ]]; then
    existed=1
    echo "[+] $label: using EXISTING mailbox $addr"
  else
    # create it (mail.tm auto-creates with a default password; we set ours)
    curl -fsS -X POST "$API/accounts" -H "Content-Type: application/json" \
      -d "{\"address\":\"$addr\",\"password\":\"$pw\"}" -o "$jar" 2>/dev/null \
      || { echo "[-] $label: mail.tm creation/login failed for $addr (rate limit? wrong password?)"; return 1; }
    token=$(curl -fsS -X POST "$API/token" -H "Content-Type: application/json" \
      -d "{\"address\":\"$addr\",\"password\":\"$pw\"}" \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
    echo "[+] $label: created mailbox $addr"
  fi
  echo "$token" > "$jar.token"
  echo "    credentials: $addr / $pw   (used for target login if requested)"
}

# --- wait for mail from the target, print links ---
wait_confirmation() {
  local label="$1" addr="$2" jar="$3"
  echo "[*] $label: waiting for mail to $addr (60s)…"
  for i in $(seq 1 12); do
    sleep 5
    local msgs first_id
    msgs=$(curl -fsS -H "Authorization: Bearer $(cat "$jar.token")" "$API/messages" 2>/dev/null || echo "[]")
    first_id=$(echo "$msgs" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[0]['id'] if d and d[0].get('id') else '')" 2>/dev/null || echo "")
    if [[ -n "$first_id" ]]; then
      echo "[+] $label: mail received — id=$first_id"
      curl -fsS -H "Authorization: Bearer $(cat "$jar.token")" "$API/messages/$first_id" \
        | python3 -c "
import sys,json,re
d=json.load(sys.stdin)
print('subject:', d.get('subject',''))
print('intro:', d.get('intro',''))
html=d.get('html','') or ''
links=[l for l in re.findall(r'https?://[^\s\"<>]+', html)]
print('--- links ---')
[print('  '+l) for l in dict.fromkeys(links)]"
      return 0
    fi
  done
  echo "[-] $label: no mail within 60s — confirm the target actually sends to mail.tm"
}

# --- login to target with given creds, capture session cookie ---
login_target() {
  local label="$1" addr="$2" pw="$3" jar="/tmp/target_${label,,}.jar"
  if [[ -z "$LOGIN_URL" ]]; then
    echo "[*] $label: no --login-url given — complete signup/login on $TARGET"
    echo "    with $addr / $pw manually, then paste the session cookie."
    return 0
  fi
  echo "[*] $label: logging into $LOGIN_URL (fields $U_FIELD/$P_FIELD)…"
  curl -sS -c "$jar" -X POST "$LOGIN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "$U_FIELD=$addr" \
    --data-urlencode "$P_FIELD=$pw" \
    -o /dev/null -w "    login status: %{http_code}\n" || true
  local sess
  sess=$(awk '{print $6"="$7}' "$jar" 2>/dev/null | grep -v '^#' | grep -v '^=' | tr '\n' ' ')
  if [[ -n "$sess" ]]; then
    echo "[+] $label session cookie: $sess"
    echo "    → paste into ledger/cookies_session.json (label $label, status: filled)"
  else
    echo "[-] $label: no session cookie captured — login in a browser and paste the cookie."
  fi
}

echo "[*] target: $TARGET"
setup_mailbox "A" "$EMAIL_A" "$PASS_A" "$JAR_A" || true
setup_mailbox "B" "$EMAIL_B" "$PASS_B" "$JAR_B" || true

wait_confirmation "A" "$EMAIL_A" "$JAR_A" || true
wait_confirmation "B" "$EMAIL_B" "$JAR_B" || true

login_target "A" "$EMAIL_A" "$PASS_A" || true
login_target "B" "$EMAIL_B" "$PASS_B" || true

echo "[*] done. Fill ledger/cookies_session.json (status: filled) and re-check the completion gate."
