---
name: authentication
description: >-
  Authentication bypass — session fixation/hijack, reset poisoning, token prediction,
  magic-link abuse, SAML XSW, rate-limit evasion, enumeration oracles, logout gaps.
  Auto-invoke when: login/signup/reset/magic-link flows, session cookies pre/post auth,
  SAML/SSO assertions, remember-me tokens, rate-limited auth endpoints. Do NOT load for:
  email-change/reset-token THEFT chains → `account_takeover`; 2FA step → `mfa`.
family: state-machine
severity: high → critical
---

# Authentication — login · session · reset · SSO bypasses

> **Arsenal:** log in as any user, forge/reset sessions, bypass SSO, brute-rate-limited doors.
> **Sibling:** `account_takeover` (points at the victim's account specifically), `mfa`
> (second factor), `jwt` (token crypto), `oauth` (federated login).
> **Proof bar:** you authenticate as an account you don't control, or a victim's session
> is captured/replayed, or a reset token predicted/leaked and used.
> **Setup:** A + B accounts; where registration is forbidden mark `unavailable` honestly.

## WAF Bypass (auth)
- Rate-limit bypass: rotate `X-Forwarded-For`/`X-Real-IP`, append params (`?x=1`), switch HTTP/1.1 vs HTTP/2 streams, add cookies
- Normalization collisions create NEW accounts: `victim` vs `victim%20`, `VICTIM`, `victim+`, unicode confusables (`а` Cyrillic)
- POST-vs-GET on the same login endpoint — different handling of locks/limits
- Duplicate headers/params (HPP) to skip the check the WAF pattern-matched

## Context
- Auth bugs live in the LIFECYCLE: initial credential check, session issuance, verification of
  resets/links, revocation at logout, token expiry, lockouts. Sketch the full sequence before testing.
- Two classes: (1) getting IN as someone else, (2) keeping/stealing the proof of being in.

## General Techniques
- **Account enumeration:** 200-vs-404, different messages/timing on login/signup/reset for existing vs new emails
- **Session fixation:** inject your session id pre-auth via `?sessionid=`/cookie, victim logs in → you carry authenticated session
- **No logout invalidation:** stolen cookies survive logout → replay after victim changes password
- **Reset-token in response:** token or reset link returned in the API body/referrer/logs
- **Reset-token prediction:** timestamp/uid-seeded tokens → predict; v1 UUID seeds → `uuidgen` enumeration
- **Magic-link abuse:** link unbound to session (reusable), no expiry, token in URL logged by shared infra
- **SAML XSW (XML signature wrapping):** duplicate `<saml:Subject>`/`<ds:Signature>` — validator checks one, consumer reads the other
- **IdP fail-open:** invalid/empty SAML assertion accepted; assertion without signature accepted
- **Rate-limit evasion on OTP/password:** session-rotation counters, param variation, 2.5 req/s ceiling
- **Remember-me abuse:** forgeable cookie = `base64(user:md5(pass))` legacy patterns — decode and check the formula
- **Login-type confusion (OAuth/magic link/login form):** same endpoint, trust the ATTACKER'S assertion type
- **Trusted-device cookie theft:** device token unbound to password changes
- **QR-code login:** QR payload swap → bind attacker device to victim account

## Second-Order & Bypass Techniques
- Reset flow emails an API token → reuse that token on the NEXT endpoint in a different context
- Register-then-reset paradox: signup upsert overwrites existing account's password (→ `account_takeover`)
- Token generated but never invalidated across flows (reset + email-change reuse same token)

## Auth Bypass Techniques
- Client-side trust: response `"authenticated":false` → flip to `true` (some SPAs honor it)
- `skipOldPwdCheck`-class action params in reset (pre-auth password reset)
- Login as `admin` with empty password where backend skips empty-field checks
- SQLi-in-login (→ `sqli`): `' OR 1=1-- -` on username; NoSQL `{"$ne":null}` (→ `nosqli`)
- Default creds sweep on admin panels (root/admin/`admin123`, `tomcat/tomcat`…)
- Direct object ref to session store: `/sessions/<id>` without binding check (→ `access-control`)

## Header Techniques
- `Host`-header poisoning of reset links (→ `account_takeover` for the full chain)
- `X-Forwarded-Host`/`Forwarded` building callback URLs in SSO flows
- `X-Forwarded-For` trusted for lockout decisions — spoof to keep brute-forcing

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-31581 | Apache BasicAuth webdav | cache/auth bypass via headers |
| CVE-2019-11248 | Kubernetes | partial-auth: legacy token headers |
| CVE-2018-0114 | Cisco ASA | unauthenticated path bypass |
| CVE-2009-3376 / SAML libs | Shibboleth/OneLogin legacy | SAML signature wrapping |

## Indicators — record as `possible` when seen
- Different response/time/status per email existence · reset link/token in response body, referer, logs
- Cookie with predictable parts (base64 of user id, timestamps, `user=<id>` visible)
- `remember_me`/`trusted_device`/`auto_login` cookies · QR login · SAML assertions accepted without cert pinning
- Lockout counters resettable by changing IP/param/session; 429 bypassable

## Tools
- Burp: send reset → inspect Link/cookie for tokens; Repeater for SAML manipulation (Burp SAML Raider)
- `ffuf -w emails.txt -u URL/forgot -d 'email=FUZZ' -mr 'exists|not found'` for enumeration oracle
- `hashcat -m 3200` only on YOUR OWN captured hashes; `jwt_tool` for token claims (→ jwt)
- Browser devtools for SPA response-flag flipping; mail.tm inbox (`tools/capture_session.sh`) for token capture