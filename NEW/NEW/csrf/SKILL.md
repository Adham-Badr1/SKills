---
name: csrf
description: >-
  CSRF — missing tokens, origin/referer gaps, method-verb bypass, content-type
  confusion, double-submit/cookie-binding flaws, GET-based state change, OAuth linking
  CSRF, stored passive triggers. Auto-invoke when: state-changing forms/JSON without
  tokens, no Origin/Sec-Fetch-Site checks, GET endpoints that mutate, `_method`/
  override headers, SameSite lax flows, cookie-authenticated actions. Do NOT load for:
  token-issuing login flows → `authentication`; OAuth state issues → `oauth`.
family: state-machine
severity: medium → high
---

# CSRF — token gaps · origin gaps · verb gaps · same-site chains

> **Arsenal:** force authenticated victims to change email/password, transfer money, link
> attacker accounts, disable 2FA.
> **Sibling:** `oauth` (account-linking CSRF), `graphql` (GET-transportable mutations),
> `access-control` context sometimes needed for token-read chains, `xss` (pure XSS
> outranks CSRF).
> **Proof bar:** with ONLY a victim session (no XSS, no credentials), a state change
> happens. Verified via state read-back (email changed, balance moved). A missing token
> alone is `possible`.
> **Setup:** A-target/victim browser-like session; craft the hostile page/request in a
> test profile where you control the victim cookie.

## WAF Bypass (CSRF)
- Content-type confusion: JSON expects `application/json` → send `text/plain`/form-urlencoded — CORS preflight skipped, CSRF lives
- Method override: `X-HTTP-Method-Override: PUT` / `_method=PUT` — CSRF-protected verb gate skipped via POST
- SameSite=Lax gap: Lax allows top-level GET → use GET-based CSRF / redirect chains for top-nav
- Origin null: sandboxed iframe `sandbox="" allow-scripts` → `Origin: null` accepted by naive checks
- Same-site client-side redirects: `?next=/logout` chains to cross-origin POST while cookie sent (SameSite=Strict edge)
- Token duplication bypass: if token also in cookie (double-submit), inject cookie via subdomain CRLF/`__Host-` absence

## Context
- CSRF = state-changing request that authenticates via cookies but has no unforgeable
  proof of the user's intent. Modern defenses: CSRF token, Origin/Sec-Fetch-Site checks,
  SameSite cookies, re-auth. Test each line, in order: token presence → token binding →
  origin checks → SameSite → method gates.
- APIs with Bearer tokens are usually safe; COOKIE-authenticated JSON APIs are the sweet spot (CORS preflight confusion).

## General Techniques
- **Baseline no-token:** state change with no token → direct CSRF
- **Token presence-check only:** server validates token EXISTS but not WHO it belongs to — use your own valid token cross-user
- **Token not session-bound:** token generated pre-login reused after login of another user
- **Double-submit:** token duplicated in cookie — cookie injection via path/subdomain-precursor
- **Origin/Referer bypass:** `Origin: null` (iframe sandbox), empty Origin, `Origin: https://evil.com` accepted when check is on Referer only
- **GET CSRF:** state change over GET (img/link driven)
- **Method override:** POST+`X-HTTP-Method-Override` to reach PUT/PATCH/DELETE handlers
- **Content-type trick:** `text/plain` JSON POST executes handler, skips preflight
- **Cross-site JSONP handler:** `callback` executes with credentials — call state-changing JSONP
- **OAuth account-linking CSRF:** attacker state token → victim's account links attacker's identity (→ `oauth`)
- **Stored passive trigger:** attacker-uploaded content (SVG/HTML/seed) fires same-site fetch on view — CSRF without victim navigation (stored-XSS-neighbor)

## Second-Order & Bypass Techniques
- Token in URL + Referer leak: page A's anti-CSRF leaks to cross-origin subresource → replay
- SameSite=Lax: top-level GET navigations carry cookies — dual GET+POST chain with redirect
- 2FA/email-change CSRF: sensitive flows WITHOUT re-auth are CSRF + ATO fuel (→ `account_takeover`)

## Auth Bypass Techniques
- CSRF against login/logout endpoints = login CSRF: force victim into ATTACKER's account
- Token rotated at login but validated after → race the rotation with parallel requests (→ `race_condition`)
- Anti-CSRF header but no token: `X-CSRF-Token` with ANY random value accepted (presence-only)

## Header Techniques
- `Origin`/`Sec-Fetch-Site: cross-site` — are they checked? `Origin: null` crafted in sandboxed iframe
- `SameSite` cookie attribute — Lax/None sites are chimneys for GET-CSRF
- `X-Requested-With`/`X-CSRF-Token` presence-only checks — supply arbitrary values

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2020-35489 | WordPress < 5.5.1 | unauth CSRF (comment flood) |
| CVE-2021-40438 (Apache) | mod_proxy | path traversal → CSRF-ish authz bypass |
| CVE-2019-7196 | GitLab < 12.1.5 | SSRF+CSRF chain classic |
| CVE-2020-10701 | libnss3 | null-origin CSRF edge (rare) |

## Indicators — record as `possible` when seen
- POST/PUT forms or JSON without visible CSRF token · token unbound (same value across users/sessions)
- No Origin/Sec-Fetch-Site validation on state changes · GET handlers that mutate (see 200s on GET for POST routes)
- Cookie-auth + JSON endpoints without SameSite · double-submit pattern (token in cookie AND body)
- Email/password/2FA endpoints without re-authentication

## Tools
- Burp: automate "drop token, replay request" macro; same for flipped method
- HTML harness: `<form action="URL" method="POST">` auto-submit page; `sandbox="allow-scripts"` iframe for Origin:null
- `curl -s -X POST URL/change_email -d 'email=x@y.z'` without token — observe 403 vs 200
- Compare `Sec-Fetch-Site: cross-site` requests: send with random Origin header