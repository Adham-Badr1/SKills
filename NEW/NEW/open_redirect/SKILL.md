---
name: open_redirect
description: >-
  Open redirect — unvalidated redirect params, allowlist/parser bypasses (//, \, @,
  encoded, unicode-dot, CRLF), Host/X-Forwarded-Host driven Location, meta/JS sinks,
  OAuth RelayState abuse. Auto-invoke when: url/next/return/dest/target/continue/
  returnTo/redirect_uri/RelayState params are reflected into Location/JS/meta,
  login/OAuth callbacks build redirects, backend fetch follows redirects. Do NOT load
  for: server-side fetch of the URL → `ssrf`; OAuth flows → `oauth`.
family: sink-signal
severity: low → medium
---

# Open Redirect — params · hosts · parser gaps → token/phishing chains

> **Arsenal:** phishing cover, OAuth token theft, SSRF filter bypass, session-hygiene chains.
> **Sibling:** `oauth` (redirect_uri surface), `ssrf` (server-side follow), `xss`
> (JS-sink redirects can become XSS), phishing → `osint` (harvesting).
> **Proof bar:** the app issues a Location/meta-refresh/JS-navigation to an attacker
> domain on YOUR input; for chains: prove the token/cookie actually leaves (callback).
> **Setup:** benign test: `/login?next=https://evil.example` → observe 302/303/JS.
> Redirect-param modifications must be logged per-endpoint — each is a separate item.

## WAF Bypass (redirect)
- Scheme-relative: `//evil.com` (browser follows) · backslash `\evil.com` · `javascript:alert(1)` where scheme checked as prefix only
- `@`-trick: `https://evil.com@trusted.com` (userinfo confusion) · `https://trusted.com.evil/` (substring whitelist)
- Parser differentials: `https:evil.com`, `https:/evil.com`, `////evil.com`, CRLF `%0d%0a` (header injection or binary redirect)
- Encoded: `%2f%2fevil.com`, double-encoding `%252f%252fevil.com` (WAF decodes once)
- Unicode dot `evil。com`, `evil／com` fullwidth slash, homoglyph hosts `.` → `·` in browser IDN
- Null byte `%00`, `?`/`#` injection to cut validation: `trusted.com#@evil.com` fragment re-parse
- Path-relative tilt: `//evil.com` from `/logout` path · `../` chains `/%2e%2e//evil.com`

## Context
- Redirect builders concentrate in: login/logout (`next`, `returnTo`), OAuth (`redirect_uri`,
  `RelayState`), language/theme (`url`, `target`), error handlers (`err=...`), payment callbacks
  (`callback`, `success_url`), and Host-header-driven `Location` builders.
- Verify BOTH the validation layer (server allowlist) and the consumer (browser parser) — the bug
  is usually the mismatch.

## General Techniques
- **Param echo:** `next`/`url`/`return_to`/`continue`/`dest`/`redirect` reflected unvalidated
- **Host header redirect:** app builds `Location: https://${Host}/path` → `Host: attacker.com` → victim follows
- **X-Forwarded-Host:** same builder trusting the header chain
- **Meta refresh:** `<meta http-equiv="refresh" content="0;url=USER">` sinks
- **JS sink:** `window.location = USER` / `location.href` / `document.location` → check for `javascript:` acceptance
- **CRLF / header injection:** `%0d%0aLocation: https://evil.com` when newline unsanitized in Location builder
- **OAuth RelayState:** SAML `RelayState` echoed into post-auth redirect — swap to evil
- **`javascript:` scheme:** allowed when validator only checks `http://` prefix
- **Data-URI:** `data:text/html,<script>…` where scheme allowlist incomplete

## Second-Order & Bypass Techniques
- Whitelist check on DECODED value, redirect on RAW (and vice versa) — double-encode dance
- `trusted.com@evil.com` → passes contain-check, browser goes to evil.com userinfo trick
- Semicolon path trick: `trusted.com;evil.com` / `trusted.com%2f..%2fevil.com` path traversal in URL

## Auth Bypass Techniques
- OAuth `redirect_uri` open redirect → code theft (→ `oauth`) — highest-impact redirect usage
- Password-reset `next` param → token-bearing redirect to attacker (→ `account_takeover`)
- Login callback trusts `returnTo` for post-auth destination — POST your poisoned URL to the victim

## Header Techniques
- `Host`, `X-Forwarded-Host`, `Forwarded`, `X-Original-URL`-family in Location builders
- `Referer`-based default redirect (falls back to Referer of login page — attacker can set it)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-20222/20223 | Keycloak 12 | redirect_uri validation bypass |
| CVE-2019-10194 | Keycloak ≤8 | open redirect in auth flows |
| CVE-2020-24659 | Unbound/NSD | DNS rebinding redirect (edge) |
| CVE-2018-0732 | Spring Social | `afterLogin` redirect param |

## Indicators — record as `possible` when seen
- Any of `redirect|next|url|dest|return|continue|returnTo|callback|goto|target|relaystate` in URLs
- 302 Location reflecting your value · meta-refresh/JS redirect sinks in responses
- `Host`-header manual swap renders the host into Location · OAuth callback with open redirector behind it

## Tools
- `ffuf -w redirs.txt -u 'URL/login?next=FUZZ' -mr 'Location:.*FUZZ|evil'` per-endpoint
- `curl -si 'URL/login?next=//evil.example' | grep -i location`
- OpenRedireX / Burp's redirect scanner; browser devtools for JS-sink redirects (`window.location`)