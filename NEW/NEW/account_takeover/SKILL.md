---
name: account_takeover
description: >-
  Account takeover chains — username collision resets, email-change without re-auth,
  email-change IDOR, one-click ATO, reset poisoning, token/OTP flaws, registration-as-
  reset, pre-ATO. Auto-invoke when: password-reset/forgot-password flows, email-change
  settings, reset tokens in APIs or URLs, magic links, OTP verification. Do NOT load
  for: login/session mechanics themselves → `authentication`; 2FA step → `mfa`.
family: state-machine
severity: critical
---

# Account Takeover — reset · email-change · token · magic-link ATO

> **Arsenal:** full ATO of any account — read, mutate, exfiltrate, escalate to admin.
> **Sibling:** `authentication` (generic auth), `oauth` (account linking), `csrf` (state
> change), `access-control` (IDOR-based starts), `xss` (session theft).
> **Proof bar:** you authenticate as the victim AND demonstrate control — login with the
> changed password/email, or execute the victim's state change (reset their email).
> **Setup:** A (attacker) + B (victim) accounts; B's inbox readable via mail.tm or user token.

## WAF Bypass (ATO targets)
- Token extraction through rate-limit gaps: rotate IP params, session-rotation to reset OTP counters
- Enumeration normalization bypass: `victim@x.com` vs `victim@x.com.` vs `VIRTIM...` typosquat same-acct
- Email param manipulation: `email=b@x.com&email=a@x.com` dup — reset delivers to attacker param
- Host-header of reset link: `Host: evil.com` → link base poisoned (WAF rarely inspects)

## Context
- ATO = any path where a normal user eventually gains control of ANOTHER account's credentials
  or session. Sketch: registration → login → reset → email-change → magic-link → OAuth-link, and
  test each state transition for missing re-auth and missing ownership verification.

## General Techniques
- **Username collision reset:** `victim` + whitespace-normalized identifier → attacker's `victim ` gets B's reset
- **Email change without re-auth:** change email without password/MFA → confirm → password resets go to attacker inbox
- **Email-change IDOR:** client-supplied `accountId` in change-workflow → start on B's account
- **One-click ATO:** attacker's email-change confirm link clicked by VICTIM'S session (they're logged in) confirms attacker email
- **Reset poisoning:** `Host`/`X-Forwarded-Host: attacker.com` → reset link sent to B carries attacker base → click = token leak
- **Email param manipulation:** reset delivered to attacker-controlled field (`email=` on the API, not the server-decided one)
- **Token in API response:** reset endpoint returns token in body → use directly
- **Token/account binding gap:** your own valid token works on B's uid (swap id in reset confirm)
- **No-token reset:** missing "token was generated" check — reset accepted with no token at all
- **Arbitrary pre-auth reset:** `skipOldPwdCheck=true` action param honored
- **Predictable token:** timestamp/uid/sequential/watered-down entropy → generate B's token
- **OTP flaws:** not bound to action (any code), multi-value smuggling (`code=1234&code=5678`), weak space
- **Registration-as-reset:** signup upsert overwrites B's existing account password
- **Magic-link:** unbound (reusable), non-expiring, predictable, or leaky (referer/log)
- **Pre-ATO:** plant identity on unclaimed email → victim signs up later gets your binding
- **OTP brute via session rotation:** rotate sessions to reset attempt counter (→ `race_condition` for parallel)

## Second-Order & Bypass Techniques
- Password-reset email contains OLD session token → replay after email change
- Forgot-password front door blocked, but forgot-username/SMS path leaks reset to attacker — enumerate ALL recovery surfaces
- Support-tool (Zendesk/admin) email change with weak verification (question/answer predictable)

## Auth Bypass Techniques
- Reset token usable against ANY account (token not bound to user) — generate yours, swap victim's
- OTP verified on a DIFFERENT action than the one protecting (verify `change_email`, then abuse `reset_password` token reuse)
- Response manipulation: `requires_2fa:false` flip on reset completion

## Header Techniques
- `Host`/`X-Forwarded-Host` for link-base poisoning — full ATO chain needs the victim to click
- `Referer` leakage: reset token URL shared to attacker's page in header

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-21341 | ATLASSIAN SDK | reset token in URL (referer leak) |
| CVE-2019-10309 | Jenkins | password hash disclosure via reset |
| CVE-2008-0073 | WordPress < 2.3.1 | reset-key injection (legacy) |
| CVE-2019-9670 (Zimbra) | Zimbra 8.7.11 | pre-auth XXE → ATO chain classic |

## Indicators — record as `possible` when seen
- Reset/verify endpoints accept email param variants · reset link returned in response/Referer
- Email-change requires no current password · token visible in URL/body · OTP code in response
- Signup responds 200/`already exists` with upsert behavior · accountId/uid client-supplied in flows
- Magic links that survive reuse or don't expire

## Tools
- mail.tm inbox automation (`tools/capture_session.sh`) — catch every reset/magic-link
- Burp macros: capture reset token from email, replay with swapped uid
- `curl -b A -X POST -d 'email=b@x.com' URL/api/account/email` (change without reauth test)
- OTP brute: `ffuf -w otps.txt -d 'code=FUZZ' -fr 'invalid'` with session-rotation wrapper