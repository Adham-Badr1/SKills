---
name: access-control
description: >-
  Broken access control — IDOR/BOLA, BFLA, BOPLA/mass-assignment, privesc, revocation
  gaps, enumeration oracles, parser differentials. Auto-invoke when: object ids
  (id/uuid/user_id/order/doc/lead/file_id) in path/query/JSON, admin/role params,
  tenant fields, stale-session flows, UI-disabled-but-callable functions. Do NOT load
  for: unauthenticated API endpoints → use `api`; 2FA-gated escalation → `mfa`.
family: state-machine
severity: medium → critical
---

# Access Control — IDOR · BFLA · BOPLA · privesc · revocation

> **Arsenal:** read/write any object cross-account, call privileged functions, escalate
> roles, mass-enum PII → ATO.
> **Sibling:** `api` (auth-agnostic endpoints), `mfa` (factor gates), `jwt` (forged
> identity), `business-logic` (entitlement misuse).
> **Proof bar:** cross-account data leak (A reads B's private data), or observed state
> change (B's role/data mutated by A). 200-with-your-own-data is never proof.
> **Setup:** TWO accounts mandatory — `ledger/cookies_session.json` A and B; establish a
> B-only secret (email marker, private field) BEFORE attacking.

## WAF Bypass (access control)
- Path normalization: `/api/admin` → `/%2e/admin`, `/api/..;/admin` (Tomcat/ASP.NET), trailing dot/slash, case-flip
- Header overrides: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-For: 127.0.0.1` — reverse-proxy authz gaps
- Method rotation: GET blocked → POST/PUT/PATCH/DELETE/OPTIONS accepted (BFLA via method)
- Version/rotation: `/v1` weak legacy → `/v2` hardened (and vice versa); `X-Api-Version: 1`
- Duplicate/array params: `?id=42&id=41` last-wins (PHP) vs first-wins (ASP) parser split; `id[]=42` confuses middleware authz
- Encoded ids: base64/hex/base36 → decode, tweak, re-encode (`aGVsbG8=` → modify last byte)

## Context
- Authorization must be checked per-object server-side; bugs hide in middleware doing the check on
  the WRONG value (body vs path, first vs last param, decoded vs raw), or in objects created before
  the check, or in endpoints forgotten by the authz refactor. UI-disabled ≠ backend-disabled.

## General Techniques
- **IDOR direct:** swap `id`/`uuid` in path/query/body with B's id while using A's session → A reads B
- **BOLA same-object:** B's object id in a list/detail/update/delete call as A
- **BFLA:** low-priv token calls admin/debug/internal endpoints (enumerate admin functions first)
- **Mass assignment / BOPLA:** add `is_admin:true`, `role:"admin"`, `permissions:[…]` to JSON — server auto-binds
- **Enumeration oracle:** 200-vs-404 / 403-vs-404 / different body lengths on existing vs random ids
- **Predictable ids:** sequential ints, timestamps, UUIDv1 → iterate for mass PII
- **Client-trusted entitlement flags:** `isPro:true` in request → server honors
- **Stale object refs:** deleted users' objects still accessible (no cascade authz)
- **Revocation gap:** after staff-remove/role-drop session still holds old rights
- **Referer/Origin-trusted authz:** some frameworks authorize based on Referer header
- **GraphQL/API nesting:** object of object (`order.user.creditCard`) — check authz at EVERY node
- **UI-hidden ≠ gone:** call disabled buttons' endpoints directly

## Second-Order & Bypass Techniques
- Objects returned inside arrays/nested responses escape the single-object check (payload carries them)
- Ownership check on the REQUEST body id but operation on HEADER/query id — mismatch
- Multi-tenant: switch `tenant_id`/`organization` while keeping own session → cross-tenant read

## Auth Bypass Techniques
- IDOR on session endpoints: read/modify ANOTHER user's session/profile via user_id param
- Email-change IDOR: client-supplied accountId starts the change on B's account (→ `account_takeover`)
- Password reset IDOR: `uid`-selectable reset → victim's reset — (→ `account_takeover`/`authentication`)

## Header Techniques
- `X-Forwarded-For: 127.0.0.1` / `X-Real-IP: 127.0.0.1` — admin authz trusting internal proxy
- `X-Original-URL`/`X-Rewrite-URL` — front-proxy admin path disclosure
- `Referer: https://admin.example.com/` — naive Referer-based authz

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2020-35730 | Roundcube | parameter-based ACL bypass |
| CVE-2021-40438 | Apache HTTPd < 2.4.49 | mod_proxy path authz bypass |
| CVE-2021-43798 | Grafana < 8.3.1 | path traversal → plugin file read (IDOR-class) |
| CVE-2019-11510 | Pulse Secure VPN | arbitrary file read via GET (authz gap) |

## Indicators — record as `possible` when seen
- Sequential/low-entropy ids in URLs · role/plan/admin/permission fields in bodies or responses
- `/admin`, `/internal`, `/v1`, `/api/debug`, `/staff` paths · tenant snippets `?org=`, `X-Tenant:`
- Two objects with identical response shape where only id differs (leads to id-list discovery)
- UI shows disable states but endpoints still 200 when called directly
- Different status codes for existing vs nonexistent objects (enumeration)

## Tools
- `curl -b "session=<A>" URL/api/orders/1042` vs B's object — diff
- Burp Autorize / AuthMatrix for BFLA sweep; `ffuf -w ids.txt -u 'URL/api/users/FUZZ' -mc 200 -b cookie_A`
- `Arjun`/`param-miner` for hidden params; jq for JSON field diffing: `diff <(curl ... B) <(curl ... A)`