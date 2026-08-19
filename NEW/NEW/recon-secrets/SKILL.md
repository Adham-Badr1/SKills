---
name: recon-secrets
description: >-
  Secrets discovery & validation — .env/.git/backup files, leaked API keys/tokens,
  credential pairs, provider validation, redacted proof. DANGER-GATED. Auto-invoke
  when: secret-like strings found (AKIA, api_key, token, password), .env/.git/config
  files, backup dumps, hardcoded keys in JS/comments, credential dumps. Do NOT load
  for: finding the files (content discovery) → `recon-endpoints`/`info_disclosure`;
  cloud key USE → `cloud_iam_privesc`.
family: sink-signal
severity: high → critical
---

# Recon-Secrets — find · validate · redact · handoff

> **Arsenal:** working credentials/keys → provider compromise, data access, ATO.
> **Sibling:** `cloud_iam_privesc` (cloud key escalation), `supply_chain` (repo
> secrets), `info_disclosure` (file discovery), `account_takeover` (credential reuse).
> **Proof bar:** a found secret VALIDATED against the provider API (token works) —
> recorded as `provider + last4 + valid:true`, NEVER the literal value. Unvalidated
> secret = `possible`.
> **Setup:** DANGER GATE: this tier is CRITICAL-class — `--allow-dangerous` required
> (APEX-HUNTER §Danger). Validation is against the PROVIDER, never the target.

## WAF Bypass (secrets)
- Case/extension rotation: `.env` `.env.local` `.env.production` `config.php.bak` `wp-config.php.bak` `db.sql` `dump.sql` `backup.zip` `secrets.json`
- Hidden dot paths: `/.aws/credentials` `/.npmrc` `/.ssh/id_rsa` `/.docker/config.json` `/.git/config` `/.netrc`
- Git history: exposed `.git` → `git-dumper` → ALL history (deleted files hold the gold)
- Wayback bodies (`waymore -mode R`) → old configs with keys; source maps carry comments (→ recon-js)

## Context
- Secrets appear where ops forgot: env files, backups, git history, JS bundles, mobile assets,
  docs, support tickets, error pages. The FIND is cheap; the VALIDATION is the skill — and the
  validation MUST hit the provider (aws sts, GitHub API, Stripe API) not the target, so a live
  key never touches the ledger or reports.

## General Techniques
- **File inventory:** ffuf/feroxbuster for the sensitive-file list (→ recon-endpoints runs it; this skill consumes hits)
- **Regex sweep:** `rg -oE '(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'` on crawled bodies/bundles/git
- **Validate AWS:** `aws sts get-caller-identity` with the key (record `provider + last4 + valid`)
- **Validate GitHub:** `curl -s -H "Authorization: token <ghp>" https://api.github.com/user` — check scope in response headers
- **Validate Stripe:** `curl -s https://api.stripe.com/v1/charges -u <sk>:`
- **Validate Slack:** `curl -s -H "Authorization: Bearer <xoxb>" https://slack.com/api/auth.test`
- **Credential pairs:** usernames+passwords in dumps/configs → client-approved reuse test (→ account_takeover)
- **DB dumps:** `db.sql` → tables with hashes → crack (client-approved) → reuse
- **JWT keys:** leaked `private.pem`/`jwt secret` → forge (→ jwt)
- **SSH keys:** `id_rsa` → try against in-scope hosts (authorized) — record only fingerprint+valid

## Second-Order & Bypass Techniques
- One key, many providers: AWS key valid + GitHub same-password → chain (→ cloud_iam_privesc/supply_chain)
- Key in a THIRD-party app (Slack webhook → channel read) → trust-chain pivot

## Auth Bypass Techniques
- Validated API key → authenticated access to admin endpoints (→ api/access-control)
- DB creds from config → direct DB connection (authorized) → data

## Header Techniques
- (n/a — file/validation tier)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (no CVEs — this is configuration; provider-version CVEs fire in owning skills) | — | — |

## Indicators — record as `possible` when seen
- Any regex-hit secret pattern in bodies/bundles/git · .env/.git/backup files present
- Config files with connection strings (`mysql://`, `postgres://`, `mongodb://`, `redis://`)
- Error pages printing env vars · wayback bodies containing old keys

## Tools
- `gitleaks detect --source .` / `trufflehog filesystem` on cloned repos (→ supply_chain)
- `rg`/`grep -aoE` regex sweeps across `urls_all.txt` response bodies (curl each, grep)
- Provider validation via their APIs (aws cli, curl) — record ONLY `provider+last4+valid:true`
- `git-dumper` for .git exposure; `strings` on mobile assets (→ android)