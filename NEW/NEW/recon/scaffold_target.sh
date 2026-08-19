#!/usr/bin/env bash
# scaffold_target.sh — build the /Hunt/<target>/ workspace for a new engagement.
# Reproduces the cms.gov tree (recon/ evidence/ findings/ ledger/ manual-testing/ …)
# so every target starts from the same ledger-driven structure.
#
# Usage:  ./scaffold_target.sh <target> ["program name / ROE note"]
# Example: ./scaffold_target.sh acme.com "Acme Public Bug Bounty 2026"
set -euo pipefail

TARGET="${1:-}"
PROGRAM="${2:-TBD — edit scope.yaml before any testing}"
if [[ -z "$TARGET" ]]; then
  echo "usage: $0 <target> [program]"; exit 1
fi
# normalize: strip scheme/path, lowercase
TARGET="${TARGET#https://}"
TARGET="${TARGET#http://}"
TARGET="${TARGET%%/*}"
TARGET="$(echo "$TARGET" | tr '[:upper:]' '[:lower:]')"

ROOT="/Hunt/$TARGET/$TARGET"
mkdir -p "$ROOT"/{logs,evidence,generated,findings/draft,findings/confirmed}
mkdir -p "$ROOT"/recon/{subdomains,resolution,alive_hosts,urls,parameters,js_files,secrets,content,osint}
mkdir -p "$ROOT"/manual-testing
mkdir -p "$ROOT"/ledger

echo "[*] scaffolded $ROOT"

# ---------- scope.yaml (template — EDIT BEFORE TESTING) ----------
if [[ ! -f "$ROOT/scope.yaml" ]]; then
cat > "$ROOT/scope.yaml" <<EOF
base_domain: $TARGET
program: "$PROGRAM"
in_scope:
  - "https://$TARGET/"          # FILL: exact in-scope roots (add subdomains/URLs)
out_of_scope:
  - ""                          # FILL: explicit exclusions (subdomains, paths, vendors)
notes_scope:
  - "FILL: any non-listed asset is OUT OF SCOPE; vendor systems excluded even if linked."
  - "FILL: redirects to vendor/external systems must NOT be followed or tested."
rate_limits:
  max_rps: 3
  burst: 2
  notes: "FILL per ROE - 429 -> back off 30s. NO rate-limit bypass/stress testing unless allowed."
deconfliction:
  - "FILL: include program tag in every request User-Agent for log deconfliction."
restrictions:
  - "FILL: ROE restrictions (no leaked creds, no DoS, minimal PoC only)."
danger_consent:
  allow_active: false           # parameter/content probing of in-scope hosts
  allow_dangerous: false        # secrets/internal tiers — NEVER flip without ROE backing
  internal_network_authorized: false
notes: |
  Authorized testing ONLY per the program ROE. DO NOT alter this file or
  collected data after the run starts — it is re-read before EVERY round.
  If /Hunt/<target> already existed, this template was SKIPPED (existing scope
  preserved). Recon command gates: no nuclei/amass unless ROE allows.
EOF
echo "[*] wrote $ROOT/scope.yaml (TEMPLATE — edit before testing)"
fi

# ---------- ledger files (flat JSON — minimal shapes) ----------
ledger_setup() {
  local f="$1" default="$2"
  if [[ ! -f "$ROOT/ledger/$f" ]]; then
    printf '%s\n' "$default" > "$ROOT/ledger/$f"
    echo "[*] wrote ledger/$f"
  fi
}

ledger_setup endpoints.json '[]'
ledger_setup js_files.json '[]'
ledger_setup ui_sections.json '[]'
ledger_setup parameters.json '[]'
ledger_setup cookies_session.json '[
  {
    "label": "A",
    "email": "account_a@mail.tm",
    "cookie": "PENDING",
    "user_id": null,
    "role": "user",
    "status": "pending",
    "acquisition": "mail.tm + target signup (tools/capture_session.sh)",
    "reason": ""
  },
  {
    "label": "B",
    "email": "account_b@mail.tm",
    "cookie": "PENDING",
    "user_id": null,
    "role": "user",
    "status": "pending",
    "acquisition": "mail.tm + target signup (tools/capture_session.sh)",
    "reason": ""
  },
  {
    "label": "admin",
    "email": "admin@'$TARGET'",
    "cookie": "PENDING",
    "user_id": null,
    "role": "admin",
    "status": "pending",
    "acquisition": "program-provided admin creds (rare) or none",
    "reason": ""
  }
]'
ledger_setup state.json '{
  "phase": "recon",
  "last_action": "scaffolded by scaffold_target.sh",
  "in_flight": null,
  "spawn_log": [],
  "loaded_skills": [],
  "completed_tiers": [],
  "pending_verification": [],
  "confirmed_findings": []
}'

# ---------- manual-testing/ mind map ----------
if [[ ! -f "$ROOT/manual-testing/README.md" ]]; then
cat > "$ROOT/manual-testing/README.md" <<'EOF'
# manual-testing/ — Pentester's Mind Map

> **Purpose:** bridge between recon output and targeted exploitation.
> Populate from `ledger/` findings; test P1 → P5 in priority order.

## Sensitivity Scoring

| Priority | Severity | Examples | Action |
|----------|----------|----------|--------|
| **P1** | Critical | Auth bypass, RCE, SQLi, mass data exposure, account takeover | Test immediately |
| **P2** | High | IDOR, BAC, stored XSS, SSRF to internal, file upload RCE | Test today |
| **P3** | Medium | Reflected XSS, open redirect, info disclosure, CSRF | Test this week |
| **P4** | Low | Missing headers, verbose errors, version disclosure | Document, test if time |
| **P5** | Info | Best practice gaps, defense-in-depth | Note for report |

## Files (create as the hunt populates them)

- `auth-flows.md` — login, register, forgot password, invite, OAuth, SAML, MFA flows
- `access-control.md` — IDOR matrix (Account A vs B), role escalation tests
- `input-validation.md` — every input point: where it lands, how it's encoded
- `file-upload.md` — upload surfaces, allowed types, validation tests
- `api-testing.md` — REST/GraphQL/gRPC endpoints, auth methods, rate limits
- `business-logic.md` — state-changing flows: payment, coupon, transfer, vote
- `session-management.md` — cookie flags, token rotation, session fixation
- `crypto-secrets.md` — hardcoded keys, tokens, credentials found in JS/source
- `chain-pivots.md` — current chain state and planned hops
- `app-map.md` — application flow map: entry points → authenticated sections

## Rules

1. Score each finding P1–P5; test P1 first.
2. Update as you test — mark tested, add new findings, note dead ends.
3. Chain greedily — confirmed primitive → add pivots to `chain-pivots.md`.
4. No finding is confirmed without raw evidence + a verifier script (exit 0).
EOF
echo "[*] wrote manual-testing/README.md"
fi

# ---------- recon/ output notes ----------
if [[ ! -f "$ROOT/recon/README.md" ]]; then
cat > "$ROOT/recon/README.md" <<'EOF'
# recon/ — tier outputs (from the recon skill / RECON playbook)

- `subdomains/`   — passive + active subdomain lists (subs.txt, subs_new.txt)
- `resolution/`   — dnsx output, alive A/AAAA, CNAMEs
- `alive_hosts/`  — httpx output: 200_alive.txt, 403_alive.txt, 5xx, tech
- `urls/`         — urls_all.txt, params.txt, param_templates.txt, gf_*.txt
- `parameters/`   — arjun/x8/param-miner findings
- `js_files/`     — downloaded bundles, linkfinder/SecretFinder output
- `secrets/`      — validated secrets (redacted placeholders only)
- `content/`      — content-discovery results (sensitive files, .git dumps)
- `osint/`        — roots.txt, asn_cidr.txt, subs_passive.txt, emails.txt,
                     leaked_secrets.txt, takeover_candidates.txt
- `tech_stack.json`      — per-host tech fingerprint summary
- `cpe_candidates.json`  — CPE matches for the CVE hunt queue
EOF
echo "[*] wrote recon/README.md"
fi

echo
echo "[*] DONE — next steps:"
echo "    1. EDIT $ROOT/scope.yaml (in_scope / out_of_scope / rate_limits / danger_consent)"
echo "    2. Load the recon skill: run OSINT first (zero-touch), then the 12 tiers"
echo "    3. Sessions: tools/capture_session.sh <target> --email-a a@mail.tm --pass-a Pw"
echo "       (reuses YOUR mail.tm inbox for login/registration; or auto-creates"
echo "       account_a@mail.tm / account_b@mail.tm) -> fills ledger/cookies_session.json"
echo "    4. Ledger contract: every discovered item = pending/tested/ignored(reason)"