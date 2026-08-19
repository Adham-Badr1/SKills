---
name: cors
description: >-
  CORS — origin reflection with credentials, null-origin trust, allowlist regex
  bypass, parser differential, wildcard subdomain abuse, missing Vary: Origin cache
  poisoning, DNS rebinding, JSONP reads. Auto-invoke when: Access-Control-Allow-* headers
  echo Origin, ACAO:*, credentialed CORS, preflight gaps, sandboxed iframes, JSONP
  callbacks. Do NOT load for: postMessage-based cross-origin messaging → `postmessage`;
  need XSS first to pivot → `xss`.
family: differential
severity: medium → high
---

# CORS — reflect · null · regex · parser · cache-poison reads

> **Arsenal:** read another-origin user's private responses (tokens, PII) from an
> attacker page, when a victim visits it.
> **Sibling:** `postmessage` (messaging channel), `xss` (to get code on a whitelisted
> origin), `access-control` (what the leaked data unlocks).
> **Proof bar:** attacker origin can READ (not just send) a credentialed response —
> demonstrated via victim-browser fetch reaching attacker and exfiltrating a secret.
> ACAO:* WITHOUT credentials is typically not exploitable for reading (but chains).
> **Setup:** victim browser victim profile; attacker page hosted on your domain.

## WAF Bypass (CORS)
- Origin reflection: server copies `Origin` header → try `https://evil.com`; prefix/suffix regex bypasses
- Null origin: `Origin: null` (sandboxed iframe/data: URI) — accepted by strict-but-null-trusting apps
- Parser differential: `Origin: https://evil.com.trusted.com`, `https://trusted.com.evil.com`, `@`-userinfo, unicode/homoglyph dot
- Header injection into Origin processing: duplicate Origin headers (first/last wins per proxy/libs)
- `Origin: null` via `data:text/html,<script>fetch…` and `srcdoc` iframes (no-network origin)
- `Origin: https://evil.com ` trailing space/CRLF variants through naive trim checks

## Context
- CORS policies matter only for reads. Server must pair `Access-Control-Allow-Credentials: true`
  with a NON-`*` origin. Audit endpoints: any place `Origin` is echoed verbatim + credentials =
  instant read primitive from any attacker page — victims just need to visit.
- JSONP is legacy CORS: callback parameter echo without allowlist = read primitive.
- Preflight analysis: which methods/headers allowed (PNA gaps with localhost too).

## General Techniques
- **Origin reflection:** `Origin: https://evil.com` → `ACAO: https://evil.com` + `ACAC: true` → read
- **Allowlist regex bypass:** prefix/suffix/partial-match weaknesses (`trusted.com` vs `trusted.com.evil.com`)
- **Null origin:** sandboxed iframe or `data:` page → `Origin: null` → ACAO null (many apps trust it)
- **Wildcard subdomain:** `*.trusted.com` trusted + a subdomain you can takeover/XSS → credentialed read (→ `subdomain_takeover`/`xss`)
- **ACAO:* without credentials:** session-less data readable anyway; chain with cookie-leak elsewhere
- **Missing Vary: Origin:** reflect origin if cached shared → cache poisoning for other users (→ `recon-js` CDN surface)
- **Legacy/null-origin on old subdomain:** parent tightened, stale host still reflects
- **DNS rebinding:** same-origin illusion to read internal/localhost APIs through victim browser (PNA gaps)
- **JSONP:** `?callback=<script>` reflection — read from attacker page; XSSI if private fields in JSONP
- **Over-broad preflight:** ACAO any + methods/headers wildcard → downstream abuse (smuggling state changes)
- **Trusted-subdomain wildcard via CORS:** `https://trusted.com` allowed — is `trusted.com` itself stale/rebinding-capable?

## Second-Order & Bypass Techniques
- Reflect `Origin` only on paths with errors/debug → query a path that triggers the open policy
- Bearer-token APIs with ACAO:* — tokens in headers NOT cookies: open CORS without ACAC still leaks (no cookies needed)
- Private Network Access: public page fetching localhost APIs (PNA preflight missing) — browser-context SSRF-ish

## Auth Bypass Techniques
- XSS on ANY allowed origin → full credentialed read through that origin (chain)
- Intranet host trusted in CORS → victim browser becomes your proxy into it (internal-network pivot via PNA)

## Header Techniques
- `Origin`, `Access-Control-Request-Method`, `Access-Control-Request-Headers` — the full preflight surface
- `Vary: Origin` absence → cache playing with reflected origins
- `Access-Control-Allow-Credentials` + `Access-Control-Allow-Headers` over-permission inventory

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2020-35951 | JetBrains TeamCity | CORS misconfig token theft |
| CVE-2019-16773 | Apache Shiro < 1.4.2 | CORS redirect auth bypass (adjacent) |
| CVE-2021-40438 + mod_proxy | Apache 2.4 | unvalidated-Origin family (legacy) |
| CVE-2019-10758 | mongo-express ≤ 0.53 | broad CORS + RCE (chain demo) |

## Indicators — record as `possible` when seen
- `Access-Control-Allow-Origin` = your reflected value (or `*` with credentials) in ANY response
- `Access-Control-Allow-Credentials: true` · JSONP `callback` params · `Origin` echoes verbatim
- Login/API on subdomain with different CORS than parent · `Vary: Origin` absent on caching layers

## Tools
- `curl -si -H 'Origin: https://evil.com' URL | grep -i 'access-control'` per endpoint
- CORS-scanner scripts / Burp extension; `ffuf -w origins.txt -H 'Origin: FUZZ' -mr 'allow-origin'`
- Browser: craft attacker page `<script>fetch('URL',{credentials:'include'})` and read response
- Compare responses across `Origin: null`, encoded dots, userinfo tricks — diff the ACAO