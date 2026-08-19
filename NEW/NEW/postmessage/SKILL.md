---
name: postmessage
description: >-
  postMessage attacks — wildcard targetOrigin, weak origin validation (indexOf/
  includes/search), sandboxed-null origins, frame-reference hijack, OAuth popup token
  theft, structured-clone gadgets, javascript: navigation, embedded SDK CSRF.
  Auto-invoke when: addEventListener('message')/onmessage listeners, postMessage with
  '*' or no targetOrigin, e.origin checks via indexOf/includes, iframes exchanging
  messages, popups posting tokens to opener. Do NOT load for: HTTP-level CORS headers
  → `cors`; XSS sinks in JS → `xss`.
family: sink-signal
severity: medium → high
---

# postMessage — listeners · origins · popups · SDK CSRF

> **Arsenal:** inject messages into vulnerable listeners → XSS, token theft from OAuth
> popups, CSRF into embedded SDKs, iframe-hijack navigations.
> **Sibling:** `xss` (DOM sinks fed by messages), `cors` (header-level cross-origin),
> `oauth` (popup flows), `open_redirect` (location sinks).
> **Proof bar:** attacker page's message triggers a DOM write / navigation / state change
> in the target origin (observed in victim browser), or a token/secret leaves the origin.
> Listener-absent-`*` alone is `possible` until an exploitable sink is shown.
> **Setup:** host an attacker page (your domain) that opens the target app in an iframe/popup.

## WAF Bypass (postMessage)
- Origin check via `indexOf('trusted.com')` → send `https://trusted.com.evil.com` / `https://evil.com/?trusted.com`
- `includes`/`startsWith`/`search` regex partials → prefix/suffix confusion
- `e.origin === location.origin` strict — fine; but `e.source` check missing → any frame can send (frame hijack)
- Sandboxed iframe: `sandbox="allow-scripts"` → `e.origin === "null"` — accepted by null-trusting apps
- `e.source` null (opener-less) trusted — attacker popup with noopener? postMessage from data: URLs
- Structured clone gadgets: `__proto__`/`constructor` in messages reaching sinks
- Message via `postMessage(..., '*')` from attacker → listener fires with any targetOrigin

## Context
- Find listeners in JS bundles: `addEventListener('message')`, `onmessage =`, and what each does
  with `event.data` — message → location/innerHTML/eval/iframe.src/storage = bug. Map the flow
  that posts TO the app: OAuth popups (`window.opener.postMessage(token, '*')`), payment/SSO SDKs.

## General Techniques
- **Wildcard receiver:** `postMessage` with `*` + sensitive data → read from any page
- **Weak origin validation:** indexOf/includes prefix-suffix bypass; regex `^https://trusted` without `$`
- **DOM-sink message:** message → `innerHTML`/`eval`/`document.write`/`location` — XSS via message (→ `xss`)
- **Iframe navigation hijack:** message → `frame.src`/`location` — navigate victim frame to attacker URL
- **Sandbox/null origin:** attacker sandboxed iframe counts as origin `null` — null-trusted listeners fire
- **OAuth popup token theft:** provider popup posts `access_token` to `*`/weak-check opener → attacker opener captures
- **Frame-reference hijack:** app posts TO `event.source` without checking — attacker's nested iframe impersonates
- **SDK CSRF (CVE-2025-59845 class):** embedded SDK accepts cross-origin messages → trigger state change in authenticated context
- **Structured-clone gadgets:** `message.data.__proto__` / constructor pollution into clone sinks
- **javascript: navigation:** message → `location='javascript:...'` / `a.href` sink where scheme allowed
- **Login/session-start listeners:** token-forgery via message BEFORE real auth (session-start listener)
- **Trusted-origin chain:** app trusts `origin` that hosts YOUR XSS → message-injected code (chain with xss)

## Second-Order & Bypass Techniques
- Post from `about:blank`/`data:` iframes (origin `null`) where the app already trusted null elsewhere
- Message queue replay: fire the same message twice with mutated `type` fields — state flip in the SDK

## Auth Bypass Techniques
- OAuth `postMessage` flow: capture the token the popup posts → authenticate as victim (→ `oauth`)
- Payment SDK: message triggers `pay()` in authenticated parent → CSRF-class charge

## Header Techniques
- `Cross-Origin-Opener-Policy`/`Cross-Origin-Embedder-Policy` absent → popup/iframe attacks easier
- `Content-Security-Policy` without `frame-ancestors` → app embeddable in attacker frames

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2025-59845 | embedded SDK (broad) | cross-origin SDK CSRF via postMessage |
| CVE-2021-41663 | (SDK family) | message-based token forgery |
| CVE-2019-5473 | GitLab API | arbitrary file read (postMessage-adjacent demo) |
| CVE-2020-8208 | Citrix | XSS via postMessage (chain demo) |

## Indicators — record as `possible` when seen
- `postMessage(..., '*')` or missing targetOrigin in bundles · `addEventListener('message')` with data→DOM sinks
- `event.origin` validated with indexOf/includes/startsWith/search/regex-partial
- OAuth/payment/SSO popups messaging opener · iframes embedded in attacker-controllable pages
- `sandbox="allow-scripts"` iframes inside the app's own pages

## Tools
- Grep JS: `rg -n "postMessage|addEventListener\(['\"]message|onmessage" js/`
- Host an attacker page: `<iframe src="TARGET">` + `window.addEventListener('message',...)` + `frames[0].postMessage(PAYLOAD,'*')`
- Browser devtools: message listener breakpoints (`addEventListener`), stack capture on `postMessage`
- Burp: match JS minified sources against listener patterns; test null-origin via `srcdoc` iframe harness