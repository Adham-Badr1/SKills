---
name: recon
description: >-
  Recon orchestrator — first contact with any target: scaffolds the /Hunt workspace,
  sequences the recon tiers, routes to recon-* sub-skills, merges outputs into the
  ledger, hands off to vuln skills. Auto-invoke when: a new apex/domain is given, a
  new in-scope host is discovered mid-hunt, or a recon tier is needed. Do NOT load for:
  a specific tier's work → use the matching `recon-*` skill.
family: sink-signal
severity: info (its outputs are the payloads)
---

# Recon — workspace · tier orchestration · handoff

> **Arsenal:** the full attack-surface map (hosts, URLs, params, JS, secrets, cloud,
> infra) seeded into the ledger for vuln hunting.
> **Sibling:** 8 sub-skills — `recon-osint`, `recon-subdomains`, `recon-infra`,
> `recon-endpoints`, `recon-js`, `recon-secrets`, `recon-cloud` — plus
> `subdomain_takeover`/`osint` for adjacent work. This file OWNS order and handoff.
> **Proof bar:** every discovered item lands in `ledger/*.json` as `pending` with a
> source; anything not worth testing is `ignored` with a reason. Silence is not completion.
> **Setup:** `/Hunt/<company>/<wildcard_domain>/` scaffold (see APEX-HUNTER §Workspace).

## WAF Bypass (recon-level)
- Passive-first: OSINT/cert-transparency/historical before a single packet (rate limits are the WAF here)
- CDN/WAF detection: `httpx -td` → note WAF; keep probing on origin IPs (→ `recon-infra`)
- Rate caps: ffuf -t 50, nuclei -t 8, katana -jc -d 3; back off on 429 — recon must never trip the gate
- Soft-404 discipline: filter same-body-for-any-path pages — 200 noise is the real enemy

## Context
- Run FIRST at engagement start, unauthenticated. Goal: build the complete surface map,
  then hand each class to its skill. Quick mode = passive+fast-active; long mode = brute/
  permute/crawl/screenshots (unattended, checkpointed — see APEX-HUNTER long-hunt).

## General Techniques (the order — each bullet = one tier → one sub-skill)
1. **Scaffold** → `/Hunt/<company>/<wildcard>/` (scope.yaml + ledger + folders) — see APEX-HUNTER
2. **OSINT** → `recon-osint` (footprint, emails, tech, ASN, passive DNS)
3. **Subdomains** → `recon-subdomains` (passive+active enumeration, resolution)
4. **Infra probing** → `recon-infra` (httpx alive/split, fingerprint, ports, 403/405 matrix)
5. **URL collection** → `recon-endpoints` (wayback/gau/katana, params, gf classes, content discovery)
6. **JS analysis** → `recon-js` (bundles → endpoints, keys, roles, source maps)
7. **Secrets** → `recon-secrets` (.env/.git/keys — DANGER-gated validation)
8. **Cloud** → `recon-cloud` (S3, CNAMEs, metadata targets, takeover candidates)
9. **Handoff** — every output → ledger `pending`; route each class to its vuln skill (table below)

**Branch router (host behavior → route):**
| Host shows | Route → |
|---|---|
| Custom app, title, interesting tech | recon-endpoints + recon-js → specialized skill |
| 403/401 on interesting path | recon-infra bypass matrix → access-control |
| `.js.map` / heavy JS | recon-js → access-control/api |
| Dangling CNAME / deprovisioned error | subdomain_takeover |
| Swagger / GraphQL introspection | recon-endpoints → api/graphql |
| Same body for every path | soft-404 → filter noise |
| Historical URL with `=` params | gf classes → sqli/xss/ssrf/redirect/idor lists |
| API versioning / /internal | api skill |
| Cloud CNAMEs / S3 / metadata hints | recon-cloud → ssrf/cloud_iam_privesc |

## Second-Order & Bypass Techniques
- Auth-profile mode: re-run crawl BEHIND a session (post-login = where high-sev bugs live); flag 401/403, don't rotate
- Origin-IP/vhost sweep behind CDN (→ recon-infra); staging hosts found via OSINT get their OWN mini-pass

## Auth Bypass Techniques
- (n/a — recon is pre-auth by design; auth probing → `authentication`/`access-control`)

## Header Techniques
- `Host`/`X-Forwarded-Host`-aware probing: vhost confusion behind shared IPs (→ recon-infra)
- User-Agent rotation for bot-blocking edge cases (mobile UA reveals mobile APIs)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (recon → CVE hits arrive via fingerprint; see the specific recon-* and vuln skills) | — | — |

## Indicators — record as `possible` when seen
- New subdomain/host → ledger + re-probe · swagger/actuator/git/graphql answers
- Version banners/tech fingerprints → CVE queue · 403s on interesting paths (locked door, not absent door)
- JS bundles with keys/endpoints · cloud CNAMEs · secrets in git history (→ recon-secrets)

## Tools (orchestration only — the tiers own their tools)
- `tools/capture_session.sh <target> [--email-a] [--pass-a]` — fills `ledger/cookies_session.json` (A/B accounts)
- `tools/scaffold_target.sh` equivalent in APEX-HUNTER §Workspace — same tree every target
- Watchdog wrap: every slow tool runs with timeout; hang never stalls the run
- Every bulk tool pipes to a FILE; ingest summaries into the ledger, never raw output