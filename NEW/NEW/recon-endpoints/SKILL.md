---
name: recon-endpoints
description: >-
  Endpoint & URL collection — historical (wayback/gau/waymore) + active crawl (katana),
  parameter harvesting, gf-classed injection lists, content discovery (hidden dirs/
  swagger/.git), OpenAPI enumeration. Auto-invoke when: recon tier 3-4 runs, params.txt
  needed, hidden content/sensitive files hunt, swagger/OpenAPI discovery. Do NOT load
  for: JS bundle analysis → `recon-js`; secrets validation → `recon-secrets`.
family: sink-signal
severity: info
---

# Recon-Endpoints — URLs · params · content · swagger

> **Arsenal:** urls_all.txt, params.txt, gf_*.txt injection-ready lists, hidden-path
> inventory, swagger/OpenAPI maps — the vuln-hunting feedstock.
> **Sibling:** `recon-js` (JS-derived endpoints), `recon-secrets` (files it flags),
> `api` (swagger consumer), `sqli`/`xss`/`ssrf`/`open_redirect` (gf list consumers).
> **Proof bar:** every recovered route lands `pending` in the ledger with a source;
> gf classes split by vulnerability family, never merged.
> **Setup:** alive.txt from recon-infra; rate limits (ffuf -t 50).

## WAF Bypass (content tier)
- Soft-404 filtering: compare bodies across fuzz paths; whitelist static/CDN/analytics noise
- Extension/backup rotation: `/.env`, `/.git/config`, `db.sql`, `config.php.bak`, `backup.zip` (→ recon-secrets)
- Swagger brute locations: `/swagger.json /openapi.json /v3/api-docs /api-docs /swagger/v1/swagger.json /redoc /api/schema /.well-known/openapi.json`
- Traversal reads: `..%2f`, `..;/` on static handlers (→ rce skill for the payload work)

## Context
- Historical archives (wayback/gau/waymore) find the FORGOTTEN endpoints — deleted routes,
  admin paths, old params. Active crawl (katana) finds the live surface. Params with `=` are
  injection gold; sort them by gf class BEFORE hunting.

## General Techniques
- **Historical:** `waybackurls $T` · `gau --threads 5 $T` · `waymore -i $T -mode U -oU` (union of Wayback+CC+URLScan+VT+AlienVault); `-mode R` downloads bodies for secret mining
- **Active crawl:** `katana -list alive.txt -d 3 -jc -kf all -silent` → urls_all.txt
- **Params:** `grep '=' | urldedupe > params.txt`; `qsreplace FUZZ > param_templates.txt`
- **gf classes:** `gf sqli; gf xss; gf ssrf; gf redirect; gf lfi; gf idor; gf rce` → gf_*.txt
- **Hidden params (long):** arjun + x8 + Burp param-miner — header/cookie/JSON key discovery (→ api)
- **Context-aware discovery:** derive method/content-type/param names from JS/Swagger/GraphQL → fuzz API routes with those (Assetnote principle)
- **Sensitive-file probe:** `.env .git/config .svn/entries .DS_Store config.php.bak backup.zip db.sql docker-compose.yml .aws/credentials wp-config.php.bak server-status actuator`
- **Exposed .git:** `.git/config` readable → `git-dumper` (→ info_disclosure/recon-secrets)
- **OpenAPI brute:** the 9 locations above → full path×verb inventory (→ api)
- **Introspection-off GraphQL:** grep bundles for persistedQuery hashes (→ graphql)

## Second-Order & Bypass Techniques
- Historical URL from a DIFFERENT subdomain era (old vhost paths now on new app) — replay onto the live host
- Wayback response bodies (`-mode R`) → secrets/old API keys (→ recon-secrets)

## Auth Bypass Techniques
- (n/a — discovery; bypassed doors hand to access-control/api)

## Header Techniques
- (n/a — content tier; header tricks live in the vuln skills)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (routes found here fire CVEs in owning skills) | — | — |

## Indicators — record as `possible` when seen
- URLs with `=` params (params.txt fuel) · swagger/api-docs/actuator answers · .git/.env/bak hits
- Forgotten admin/login routes in archives · JSON API patterns (/api/, /v1/) · GraphQL paths
- Paths with id-like segments (→ access-control) · file/page/include params (→ rce/webvuln)

## Tools
- `gau --threads 5 $T | anew urls_all.txt` · `waymore -i $T -mode U -oU` · `katana -list alive.txt -jc -d 3 -silent`
- `ffuf -w raft-medium-directories.txt -u URL/FUZZ -mc 200,301,403 -t 50` (content)
- `gf sqli` etc. from `~/.gf` patterns; `arjun -u URL` for hidden params
- `git-dumper URL/.git/ out/` when `.git/config` 200s