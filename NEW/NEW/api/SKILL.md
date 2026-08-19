---
name: api
description: >-
  API attack surface — missing auth, header trust, version rotation, hidden params,
  method/content-type rotation, mass assignment, rate-limit bypass, error-oracle
  enumeration. Auto-invoke when: /api /v1 /v2 /internal /graphql REST endpoints, JSON
  bodies with privilege fields, versioned APIs, Bearer tokens, gRPC-Web. Do NOT load
  for: object-id swaps on authenticated APIs → use `access-control`; GraphQL schema →
  `graphql`; JWTs themselves → `jwt`.
family: sink-signal
severity: medium → critical
---

# API — unauth surface · header trust · params · verbs · versions

> **Arsenal:** map undocumented endpoints, call admin functions tokenless, read/write
> beyond your role, bypass client-side gates.
> **Sibling:** `access-control` (authz bugs), `graphql` (schema surface), `jwt`
> (token integrity), `business-logic` (money logic in APIs).
> **Proof bar:** unauthenticated privileged effect, cross-account leak, or a state
> change on a resource you shouldn't touch. Enumerating a hidden route is `possible`.
> **Setup:** session A + B from `ledger/cookies_session.json` when authz classes are in
> reach; otherwise unauth probing.

## WAF Bypass (API)
- Content-type confusion: `application/json` → `text/plain`/`application/xml`/form-urlencoded — parser swap skips validation
- Method override: `X-HTTP-Method-Override: PUT`, `_method=PUT`, `?__method=DELETE` — verb gates skip
- Accept-header routing: `Accept: application/vnd.X.v2+json` routes to different handler
- Version rotation: `/v1` → `/api/v2` → `/api/mobile` → `/internal` — legacy weaker authz
- Case/normalization: `/API/users` vs `/api/users`, trailing slash, `..;/` in path
- Duplicate params: `?role=user&role=admin` — first vs last parsed by different layers
- GraphQL-ish: aliases + batching to beat rate limits (boundary → graphql)

## Context
- APIs often authenticate at the GATEWAY, not the handler: header-trust mistakes, missing authz on
  newer endpoints, hidden debug endpoints, swagger jars, mobile-only endpoints weaker than web.
- Enumerate: OpenAPI/Swagger, JS bundles (`recon-js`), GraphQL introspection, version diffs, gRPC reflection/transcoding.

## General Techniques
- **Missing auth:** call every mapped endpoint without token — expect 401/403, hunt 200s (esp. /export, /debug, /internal, /admin)
- **BFLA functions:** enumerate admin verb set from swagger/JS, fire with low-priv token
- **Hidden params:** `verbose`, `debug`, `internal`, `admin=true`, `all_fields=true`, `include=*` in JSON/query
- **Excessive data exposure:** JSON responses with password hashes/OTP/tokens/PAN fields
- **Error-oracle field enum:** response 400 messages reveal valid field names → build field inventory
- **Mass assignment:** over-post `role`/`plan`/`isActive` in create/update JSON
- **Rate-limit bypass:** rotate `X-Forwarded-For`/`X-Real-IP`, add params variation, batch in GraphQL aliases
- **Param pollution (HPP):** duplicate keys across layers (WAF vs app)
- **Multipart parser abuse:** same param in JSON body AND multipart part — different values per layer
- **gRPC-Web:** proxied gRPC with no authz — call unlisted methods; JSON transcoding gateway exposes methods as HTTP
- **API key leaks:** keys in JS, git history, mobile bundles, error pages → validate against provider API
- **Unversioned legacy:** `/api/old`, `/api/1.0`, `/api/mobile` — often pre-authz-refactor orphans

## Second-Order & Bypass Techniques
- Authenticate to get a token, then hit OLD version endpoint that validates nothing (rotation gap)
- Cookie + Bearer both present: authz checks cookie, data ops use bearer — swap mismatches
- Nested JSON: `{"user":{"id":41},"data":{"role":"admin"}}` — some binders read nested attrs without check

## Auth Bypass Techniques
- Trusted headers: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Custom-IP-Authorization`, `X-Rewrite-URL`
- `Authorization: null`/empty/`Bearer` with alg-none JWT (→ `jwt`); anonymous-role claims (`"role":""`)
- Session-when-logged-out: deleted users' tokens still valid (revocation gap)

## Header Techniques
- `X-Forwarded-*`/`X-Real-IP` rate-limit and authz spoofing
- `Origin`/`Referer` trusted for authz on some frameworks
- `Accept: application/json` vs `text/html` changing error verbosity (debug info in HTML view)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-44228 | log4j in any API stack | ${jndi:...} header/body injection → RCE |
| CVE-2022-22963 / CVE-2022-22965 | Spring Cloud Function / Spring4Shell | runtime arg/class binding → RCE |
| CVE-2020-13945 | Apache APISIX | admin API unauth (header bypass) |
| CVE-2021-22986 | F5 iControl REST | unauth API → RCE |

## Indicators — record as `possible` when seen
- Swagger/openapi json, `/api`, version prefixes, gRPC reflection service listing
- 200 on POST without token · 405s (verbs exist) · error messages listing valid fields
- Role/plan/permission keys in requests or responses · `debug`/`verbose`/`test` params
- API keys/tokens in JS bundles or git

## Tools
- `ffuf -w api-paths.txt -u URL/api/FUZZ -mc all -fc 404` (kiterunner-style router wordlist)
- Burp: Autorize (authz matrix), param-miner, content-type rotation macro
- `jq` diff of JSON responses across ids/tokens: `curl -s ... | jq . | diff - a.json`
- OpenAPI parser: `curl -s URL/swagger.json | jq '.paths | keys'`
- `katana -jc` for JS-derived endpoint harvesting; gf/`recon-endpoints` feeds this skill