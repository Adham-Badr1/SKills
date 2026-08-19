---
name: jwt
description: >-
  JWT attacks — alg confusion (none/HS256 blur), key brute-force, jku/kid injection,
  JWKS poisoning, refresh-token abuse, claim tampering, replay. Auto-invoke when:
  `Bearer eyJ...` tokens, JWT cookies (jwt, token, authorization, session), `alg`/`kid`
  in headers, key rotation endpoints (.well-known/jwks.json), refresh flows. Do NOT
  load for: opaque session cookies → `authentication`; OAuth code/token exchange → `oauth`.
family: differential
severity: high → critical
---

# JWT — crypto · alg confusion · header injection · claims

> **Arsenal:** forge tokens as any user/role, bypass signature checks, hijack refresh flows.
> **Sibling:** `oauth` (token issuance), `authentication` (session), `access-control`
> (what forged tokens unlock).
> **Proof bar:** a FORGED or tampered token is accepted — your forged claims are honored
> (admin role / victim identity) on a real endpoint. Decoding is not proof.
> **Setup:** capture your own token (login as A) and the server's public key/JWKS.

## WAF Bypass (JWT)
- None is blocked → try `"alg":"HS256"` with the PUBLIC key as HMAC secret (RS256→HS256 confusion)
- `kid` confusion: point `kid` to a file (`/dev/null`, `public.pem`), or attacker-controlled key URL
- `jku`/`x5u` header injection: server fetches your JWKS (SSRF + forgery)
- Case/typographic alg variants (`NONE`, `Alg`, unicode) through sloppy parsers
- Duplicate/splitting: two signatures (one valid one forged) — last/first-wins parser split
- `alg:none` where library treats decoded algo as instruction, not verification

## Context
- JWT flaws are library-level: verify-vs-decode misuse, algorithm confusion, header-driven key
  selection (jku/jwks), missing signature check, weak secrets, claim trust. Identify the framework:
  `jjwt`(Java), `pyjwt`, `jsonwebtoken`(Node), `jose` — each has known edge behaviors.
- Key material: RS256 public key is PUBLIC — usable as an HS256 HMAC secret.

## General Techniques
- **alg:none:** `alg:"none"`, empty signature — accepted when verification optional
- **RS256→HS256:** sign with the RSA public key as HMAC secret (smallest algorithm-confusion case)
- **ES256→HS256:** EC public key (x,y) as HMAC secret
- **HMAC secret brute:** `hashcat -m 16500 token.txt rockyou.txt` — weak secrets crack
- **kid file read:** `"kid":"../../../../dev/null"` or `/proc/self/...`-style paths — key = 0 bytes (empty secret)
- **jku/JWKS injection:** `"jku":"https://attacker.com/jwks.json"` → server fetches your keypair (also SSRF)
- **JWKS/cache poisoning:** stale cached JWK with reused `kid` — upload same-kid different-key
- **Claim tampering:** `"role":"admin"`, `"sub":"victim"` when sig not validated or sig forged
- **No expiry / replayed token:** `exp` absent or ignored — capture + replay after logout/password-change
- **JSON-vs-Compact parsing split:** JSON serialization verified, compact parsed (separate paths trust different values)
- **Refresh-token abuse:** rotation gap (old refresh reusable), scope swap, token family replay
- **SQLi through claims:** `sub`/`email` claim used verbatim in backend queries (→ `sqli`)

## Second-Order & Bypass Techniques
- Signed with one kid, verified with fallback cache (stale key still accepted) — race the rotation window
- JWE-wrapped Inner PlainJWT (`alg:none` inner token) where inner signature never verified
- Token from `/v1` accepted on `/v2` (cross-version key trust)

## Auth Bypass Techniques
- Swap claims to admin; set `"sub"` to another user; token accepted without **any** verification
- Replay captured tokens after password change (no token-version binding)
- UA-bound vs IP-bound claims: server honors client-declared binding → steal/impersonate

## Header Techniques
- `Authorization: Bearer` vs cookie vs query `?token=` — different verification paths per location?
- `jku`/`x5u`/`kid`/`iss` header-driven trust — server trusts header-chosen keys
- `alg` header driven: rotate to weaker accepted alg

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2022-23529 / 23540 | jsonwebtoken ≤ 9.0.0 | arbitrary key injection via jku |
| CVE-2020-29505 | jsonwebtoken pk-1.6.0 | no-alg accept |
| CVE-2018-0114 (JWT libs) | various ≤2018 | alg none / confusion |
| CVE-2016-5431 | nimbus-jose-jwt < 4.27 | RSA key confusion |

## Indicators — record as `possible` when seen
- JWT in Authorization/cookie/body · `.well-known/jwks.json` exposed · `kid`/`jku`/`x5u` in header
- Token accepted after tampering exp/role (log the response diff) · refresh endpoint issues reusable tokens
- Public RSA/EC key files reachable (`.pem`, `jwks_uri` internal)

## Tools
- `jwt_tool <token> -M at -t URL -rh "Cookie: jwt=<token>"` (attack matrix)
- `jwt_tool <token> -C -d wordlist.txt` (crack); `hashcat -m 16500`
- `jwt_tool --sign hs256 -k pub.pem` for confusion tests (no embedded python in skills)
- `curl -s URL/.well-known/jwks.json | jq '.keys[].kid'` — harvest kid inventory