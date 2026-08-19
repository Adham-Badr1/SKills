---
name: graphql
description: >-
  GraphQL attacks — introspection, authz gaps in resolvers, mutation abuse, aliases/
  batching, persisted queries, subscriptions, SSRF via url-fetching mutations,
  injection in arguments, CSRF via GET. Auto-invoke when: /graphql /api/gql /v1/graphql
  endpoints, `query`/`mutation` in POST bodies, introspection responses, operationName
  in JS. Do NOT load for: REST endpoints → `api`; JWT auth → `jwt`; object-ID access
  issues on REST → `access-control`.
family: sink-signal
severity: medium → critical
---

# GraphQL — schema · resolvers · mutations · aliases · batching

> **Arsenal:** dump full schema, call admin mutations unauth, cross-account reads/writes,
> brute-force 2FA in one request, DoS via depth.
> **Sibling:** `api` (REST surface), `access-control` (authz), `mfa` (alias brute),
> `csrf` (GET-transported mutations), `ssrf` (URL-fetch mutations).
> **Proof bar:** observable unauthorized effect — schema dump is `possible`; mutation
> executed cross-account/unauth, data of another user rendered, or OOB fired = confirmed.
> **Setup:** find the endpoint + capture a valid query shape from JS/network.

## WAF Bypass (GraphQL)
- Introspection off → persisted queries from JS hashes (`sha256Hash`), field-suggestion brute (`{ __typename }` → error lists valid fields), `?query=` param forms
- Endpoint rotation: `/graphql`, `/gql`, `/v1/graphql`, `/api`, `/query`, `/_graphql`, POST vs GET, WebSocket subscriptions
- Transport: `application/json` → `application/graphql` (raw query), GET with query-string, batching `[{...}]` arrays
- Obfuscation: `query` aliases `a:query`, whitespace/comment stuffing, fragment reuse to hide intent
- Case/space: `{__Schema{types{name}}}` variations; `query{__type(name:"Admin"){fields{name}}}`

## Context
- GraphQL = one endpoint, all operations. Authz must hold PER FIELD/RESOLVER, not per route —
  missed authz on nested resolvers is the norm. Map: schema (types/fields/args), operations in JS,
  then probe each mutation with the args it declares.

## General Techniques
- **Introspection:** `{__schema{types{name,fields{name,args{name}}}}}` → full API map
- **Unauth mutations:** login/createAdmin/sendEmail/export mutations fire without token
- **Authz-gap fields:** `users{email creditCards}` queryable by low-priv token (missing resolver checks)
- **IDOR via args:** pass other users' ids to `user(id:)`/`order(id:)` (→ `access-control`)
- **Mutation authz:** `updateUser(role: "admin")` — args accepted without privilege check
- **Aliases brute-force:** `login(pass:"0000") alias1..10000` — 2FA/OTP brute in ONE request (→ `mfa`)
- **Query batching:** `[q1,q2,...]` — bypass rate limits; batch-before-check races (→ `race_condition`)
- **SSRF mutations:** `avatar(url:)`, `importWebhook(url:)`, `fetch(url:)` → server fetches (→ `ssrf`)
- **Injection in args:** string args into SQL/templates → `sqli`/`ssti`/stored-XSS per arg
- **Path traversal:** file-handling resolvers with `path:` args → arbitrary file read/write (→ `rce`)
- **CSRF via GET:** mutations over GET with form-encoded body (no preflight) + cookie auth (→ `csrf`)
- **Subscriptions:** WebSocket with no auth/stale token/guessable topics → live data stream
- **Session gaps:** GraphQL session survives logout/password change (revocation gap)
- **Deactivated accounts:** disabled users keep full GraphQL access
- **Custom directives:** `@skip`/`@include`/custom directives abusable for authz skips
- **Persisted-query abuse:** register any operation as "trusted" — bypass WAF/rate-limit checks
- **Depth DoS:** deep nesting `{a{a{a{...}}}}` with expensive resolvers — resource exhaustion
- **Verbose errors:** resolver stack traces leak internals (→ `info_disclosure`)
- **Apollo Federation:** subgraphs reachable directly — router security controls bypassed

## Second-Order & Bypass Techniques
- Stored XSS via mutation → rendered unencoded in other clients (→ `xss`)
- Alias reuse across queries for state-machine races: same mutation twice in one batch, server applies both

## Auth Bypass Techniques
- Introspection-off recovery → persisted query replay from JS bundles (→ `recon-js`)
- Federation subgraph without auth → admin mutation via subgraph port/route
- `omit fields` trick: query WITHOUT the authz-required field → some resolvers skip the check (field omission)

## Header Techniques
- `X-Apollo-Operation-Name`, `PersistedQuery` header params, `apollo-require-preflight` — transport gates
- WebSocket `Sec-WebSocket-Protocol: graphql-ws` / `graphql-transport-ws` unauthenticated subscriptions

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2020-15231 | Apollo Server < 2.18.1 | persisted-query DoS |
| CVE-2022-23631 | JSON-API Go / graphql libs | header injection via args |
| CVE-2021-43143 | Apollo Federation | subgraph trust gap (family) |
| CVE-2023-2650 | OpenSearch dashboard | (adjacent) |

## Indicators — record as `possible` when seen
- POST bodies containing `"query":"..."` · `/graphql`-ish paths · introspection 200
- JS bundles with `gql\`...\``/`operationName`/`sha256Hash` · WebSocket `graphql-ws` subprotocol
- Error text: `"errors":[{"message":"Cannot query field ..."}]` — field enumeration oracle

## Tools
- `curl -s -X POST URL/graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}'`
- GraphQL map: `curl -s ... -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}' | jq '.data.__schema.types[] | select(.fields) | {name, fields: [.fields[].name]}'`
- InQL (Burp), GraphQL Raider, clairvoyance (introspection off); `ffuf -w gql-paths.txt -mc 200`
- Alias brute template: one request with 1000 aliases; validate response diff by hand