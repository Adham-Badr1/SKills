---
name: mfa
description: >-
  MFA/2FA bypass — forced browsing past the gate, token/session binding gaps, null/
  default OTP, response-flag flips, backup-code leaks, WebAuthn enrollment without
  re-auth, trust-device forgery, API tokens issued without MFA, secondary-flow gaps.
  Auto-invoke when: OTP/TOTP/2FA verify/resend/backup-code endpoints, trust-device
  cookies, MFA settings/enrollment/disable endpoints, passkey registration, API-token
  issuance. Do NOT load for: first-factor flows → `authentication`; OTP code reuse on
  reset → `account_takeover`.
family: state-machine
severity: high → critical
---

# MFA Bypass — gates · tokens · enrollment · secondary flows

> **Arsenal:** skip the factor, enroll attacker devices, mint API tokens without MFA,
> brute 2FA codes with rotated counters.
> **Sibling:** `authentication` (first factor), `access-control` (post-2FA surface),
> `business-logic` (2FA-as-payment-gate), `account_takeover` (reset+2FA chain).
> **Proof bar:** authenticate with ONLY first factor where a second is enforced (verify
> by reaching a 2FA-protected resource), or attacker factor/enrollment is active on a
> victim's account, or MFA-issued token minted without the factor.
> **Setup:** A (attacker) + B (victim); enable 2FA on YOUR account first to learn the flow.

## WAF Bypass (MFA)
- Forced browsing: hit post-2FA endpoints directly with first-factor session — middleware misses
- OTP brute via rotated sessions: change session each attempt resets the counter (→ `race_condition` parallel)
- Multi-value smuggling: `code=1234&code=5678` / array `code[]` — some validators accept any array member
- Null/empty: `code=`, `code=null`, missing param → default-true paths; `000000`/`123456` default codes
- Response flips: `"requires_2fa":false` in JSON — SPA honors it server-side flag
- Parallel flows: start 2FA in normal AND beta/normal-split flows — enforcement desync

## Context
- MFA enforcement is a STATE MACHINE: first factor → MFA challenge → verified flag → privileged
  session. Bugs hide in: endpoints skipped by the gate, tokens bound to the wrong session,
  challenges optional/forgeable, backup paths (backup codes, trust-device, recovery) weaker,
  and flows that bypass the challenge (API tokens, OAuth, invites).

## General Techniques
- **Forced browsing:** after 1FA, request `/dashboard`, `/settings`, API paths directly — no 2FA demanded?
- **Token not session-bound:** code accepted for ANY session — intercept B's session, replay A's valid code
- **Null/default OTP:** blank, `000000`, `123456`, `999999` accepted
- **OTP bound to nothing:** verify endpoint validates code against a DIFFERENT action (email-change OTP validates password reset)
- **Response manipulation:** flip `requires_2fa`/`2fa_verified` in response → app session proceeds
- **Backup codes:** readable via IDOR/CORS/XSS after generation; guessable sequence; never invalidated
- **Trust-device forge:** remember-me cookie = predictable (timestamp/base64) → craft for victim
- **WebAuthn/passkey enrollment without re-auth:** attacker authenticator added to victim account mid-session
- **API/personal token issuance without MFA:** /api/tokens endpoint reachable with 1FA-only session
- **Secondary flows:** invites, bounty claims, admin actions — 2FA enforced on login but not on actions
- **Federated login skip:** OAuth/OIDC login path skips app's MFA entirely (→ `oauth`)
- **Wide TOTP window:** ±1-2 steps accepted → brute surface widens (timing attacks on verify)
- **OTP email/SMS abuse:** no per-user cooldown → spam/DoS at the delivery endpoint
- **2FA-linking flaw:** improper verify endpoint grants OTHER-account takeover (uid-swap)
- **MFA CSRF/clickjacking:** disable-2FA endpoint without CSRF/re-auth → victim's 2FA removed (→ `csrf`)

## Second-Order & Bypass Techniques
- Deactivate account → reactivate: does the 2FA enrollment survive? (usually it does — fine; check the reverse: NEW device on reactivated account)
- Remember-me cookie stolen pre-2FA, replayed post-2FA on another device

## Auth Bypass Techniques
- 2FA enforced for password login but not for OAuth/magic-link/SAML paths — enter via the weak door
- Recovery codes stored client-side; device-loss flow skips challenge with any old cookie
- Privileged API tokens usable even after 2FA disable/enable cycle (no re-issue)

## Header Techniques
- `X-Forwarded-For` trusted for "trusted device" decisions → spoof to skip challenge
- `X-2FA-Required: false` header honored by naive middleware; `X-Device-Trusted: true`

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-42567 | Apereo CAS | MFA bypass via unauthenticated CAS login |
| CVE-2020-15766 | Greenbone/OSV | 2FA disabled via unauth endpoint |
| CVE-2019-20472 | 8x8 cloud | MFA bypass via API |
| CVE-2021-26718 | ManageEngine | auth+2FA bypass chain (family) |

## Indicators — record as `possible` when seen
- Verify/resend/backup-code endpoints reachable pre-challenge · session accepted with no challenge flag set
- Response JSON carries `2fa`/`requires_2fa`/`mfa_verified` booleans — flip candidates
- Trust-device/remember-me cookie with visible structure · WebAuthn enrollment endpoints (webauthn/authenticators)
- API token issuance with no factor · OAuth social login present alongside 2FA (bypass door)

## Tools
- `curl -s -b firstfactor cookie` direct hits on post-2FA paths (forced browsing battery)
- `ffuf -w codes.txt -d 'code=FUZZ' -fr 'invalid|wrong' -ac` with session-rotation wrapper
- Burp: parallel-flow macros (two sessions, rotate); browser devtools for response-flag flips
- WebAuthn: FIDO alliance test tools on YOUR test enrollment; check RP-ID scope cross-origin