---
name: recon-js
description: >-
  JS bundle analysis — extract endpoints, API keys, roles, admin routes, source maps,
  parameter names, secrets from JavaScript. Auto-invoke when: any .js bundle discovered,
  sourceMappingURL/.js.map seen, SPA with heavy JS, hidden frontend functions needed,
  endpoint harvest for access-control. Do NOT load for: full-file reading of every JS
  → this IS the skill; secret VALIDATION → `recon-secrets`.
family: sink-signal
severity: info → high (leaked keys)
---

# Recon-JS — bundles → endpoints · keys · roles · routes

> **Arsenal:** the hidden API map (routes never in swagger), hardcoded keys/tokens, role
> structures, admin function names — the blueprint for access-control/api hunting.
> **Sibling:** `access-control` (what the routes unlock), `api` (endpoint testing),
> `recon-secrets` (key validation), `xss` (DOM sinks found here), `postmessage`
> (message listeners found here).
> **Proof bar:** endpoint/key EXTRACTED and confirmed against the live app (endpoint
> 200s, key validates). Extraction alone = `possible`.
> **Setup:** js_files.json ledger entries from recon-endpoints crawl.

## WAF Bypass (JS mining)
- Minified bundles: beautify (`js-beautify`/`npx prettier`) then grep; source maps when available
- Source maps: `.js.map` + `sourceMappingURL` → reconstruct ORIGINAL source (routes, comments, keys)
- Obfuscation: `strings` on bundles; decoded variable names; dynamic `fetch("/api/"+x)` concat patterns
- Scoped JS: chunked bundles by route (webpack chunk names reveal feature names)

## Context
- SPAs funnel every action through JS → the bundle IS the API documentation. Roles, admin
  flags, hidden endpoints, and keys live in it. Route names in chunk files (webpack) reveal
  feature surface. Combined with `postmessage` (listeners) and `xss` (DOM sinks) it covers the
  client-side plane; server-side classes then test the harvested routes.

## General Techniques
- **Endpoint harvest:** `rg -o '["'"'](/api/[a-zA-Z0-9_/{}:-]+)'` + fetch/axios/XHR patterns
- **Key extraction:** `rg -oE '(api[_-]?key|token|secret|authorization|aws_access|bearer|password|firebase|supabase|stripe|braintree|GOOGLE|AKIA)[^,;}]{4,}'`
- **Role/flag map:** `rg -n 'admin|isAdmin|role|permissions|plan|trial|premium'` → privesc targets (→ access-control)
- **Hidden function names:** `rg -n 'function (export|download|import|admin|delete|promote|grant)'` → BFLA targets
- **Source map reconstruction:** download `.js.map`, `sourcesContent` → full original source
- **Webpack chunk inventory:** list chunk files → feature map (admin-panel chunk names!)
- **DOM sink audit:** `rg 'innerHTML|eval\(|document.write|location=|postMessage'` → xss/postmessage leads
- **API URL building:** `rg -n 'concat|template|`/api/`'` — dynamic endpoint construction
- **OAuth/SSO config:** `client_id`, `redirect_uri`, `authorization_endpoint` in JS (→ oauth)
- **GraphQL ops:** `gql\`...\``, `operationName`, `sha256Hash` persisted queries (→ graphql)
- **Version/api headers:** `X-API-Key`-style constants the app sets (→ api)
- **Third-party embeds:** analytics/chat/ads scripts = extra attack surface (→ supply_chain)

## Second-Order & Bypass Techniques
- Old bundle versions in `?v=123` cache or archive → DIFFERENT endpoints (legacy surface)
- Keys in source maps' comments (`// TODO fix key`) — maps carry what minified dropped

## Auth Bypass Techniques
- Admin routes/role-check code IN JS → directly test the backend enforcement (never trust the JS gate)
- Persisted-query hashes → replay authenticated ops unauth (→ graphql)

## Header Techniques
- (n/a — client-side tier)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (framework version in bundles → its CVE table; e.g. jQuery < 3.5.0 → CVE-2020-7071) | — | — |

## Indicators — record as `possible` when seen
- `/api/` strings in JS · `api_key`/`token`/`AKIA`/firebase/supabase/stripe patterns
- `admin`/`role`/`permissions` code paths · sourceMappingURL references · webpack chunk names
- postMessage listeners · innerHTML/eval sinks · OAuth client_id/redirect_uri config

## Tools
- `cat app.js | js-beautify > app.beauty.js`; `rg -o "['\"](https?:)?//[a-z0-9./_-]+" ` variants
- linkfinder (`linkfinder.py` runs as a standalone TOOL — allowed; the rule is no embedded python inside skills)
- SecretFinder / `nuclei -tags js` for triage; `sourcemap` extractor for `.js.map`
- Burp JS Beautifier + grep macro for endpoint/role patterns per host