---
name: subdomain_takeover
description: >-
  Subdomain takeover — dangling CNAME/NS, expired cloud IP/registrable domain, DNS
  parser differentials (trailing dot), SaaS fingerprint claiming, wildcard records,
  post-takeover trust abuse (cookies/CORS/OAuth). Auto-invoke when: CNAME→NXDOMAIN,
  deprovisioned-resource errors (NoSuchBucket/NoSuchHost/HEROKU_PAGES/pages-lookup),
  abandoned third-party records in passive DNS, wildcard forwards, parent-cookie trust.
  Do NOT load for: general subdomain discovery → `recon-subdomains`.
family: sink-signal
severity: medium → high
---

# Subdomain Takeover — dangling records → full host control

> **Arsenal:** control an in-scope subdomain: serve content, capture cookies on the
> parent domain, abuse CORS/SSO trust, phish creds.
> **Sibling:** `recon-subdomains` (discovery), `cors` (trust abuse), `access-control`
> (session trust), `osint`/`recon-cloud` (asset inventory).
> **Proof bar:** provider's claim process completed on the dangling host (you serve
> content there) or provider deprovisioned-response confirmed with claimable fingerprint.
> CNAME→NXDOMAIN alone is `possible`.
> **Setup:** none — passive DNS + provider fingerprints; NEVER attack a provider you
> don't own the account for — claim via the provider's normal flow on your own tenant.

## WAF Bypass (takeover — no WAF; it's DNS + provider policy)
- Trailing-dot parser splits: `sub.evil.com.` vs `sub.evil.com` — resolver vs registry differ
- Wildcard records: `*.evil.com` forwarding every name — find a name the wildcard serves but no A exists
- Case/NXDOMAIN split: some resolvers answer for case variants only
- IPv6-only AAAA dangling (no A) — providers that only check A records

## Context
- Takeover = a hostname whose authoritative answer points at a service you can provision.
  CNAME to AWS S3/CloudFront/Elastic Beanstalk, Azure, Heroku, GitHub Pages, Fastly, Netlify,
  Zendesk, Shopify, Sendgrid, Wordpress.com, etc. The provider's "no resource here" response
  proves claimability — check against can-i-take-over-xyz fingerprints.

## General Techniques
- **Dangling CNAME:** `dig +short sub CNAME` → target hostname fails DNS/provision → claim in provider console
- **Expired cloud IP:** A-record to deprovisioned EC2/cloud IP — reallocate IP → serve content
- **Expired registrable domain:** name points at a domain you can register (dropped)
- **Dead NS delegation:** `dig NS` → nonexistent nameserver hosts → register that host → control DNS
- **SaaS fingerprint claiming:** NoSuchBucket (S3), "There isn't a GitHub Pages site here" (Pages), HEROKU_NO_SUCH_APP, pages "lookup failed" (Fastly), Zendesk "help center not found"
- **Wildcard amplification:** wildcard record exists; specific sub resolves to claimable service — test each
- **Email/MX control proof:** MX points at claimable mail service → control the domain's mail
- **Post-takeover trust abuse:** parent sets cookies for `.evil.com`/`*.evil.com`; OAuth/CSP/SSO whitelists the taken host → session/code theft (→ `cors`/`oauth`)

## Second-Order & Bypass Techniques
- Parent cookie scoping: after takeover, set `sessionid` for the parent domain via the controlled subdomain (cookie-jar poisoning on HTTP)
- CORS allowlist includes the dead host → now your host → credentialed reads (→ `cors`)
- CSP `script-src` includes it → script injection into parent pages

## Auth Bypass Techniques
- SSO/IdP callback whitelist includes the taken subdomain → impersonate the SSO callback
- OAuth redirect_uri allowlist → token capture (→ `oauth`)
- Password-reset link builder using the taken subdomain → victim resets flow through you

## Header Techniques
- Host-header routing: does the app route by Host and trust subdomain=tenant? take the tenant via the dead host
- `Access-Control-Allow-Origin` trusting the taken subdomain

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2020-15922 | GitLab (cloud) | takeover-class trust abuse |
| CVE-2019-19781 (adjacent) | Citrix ADC | (authz family, not takeover) |
| CVE-2021-27409 | Zendesk-class | help-center takeover chain |
| (takeover = config bug; no stable CVE) | provider classes | fingerprint-driven |

## Indicators — record as `possible` when seen
- `dig +short <sub> CNAME` → host outside the org's own infra · NXDOMAIN on the CNAME target
- HTTP responses: `NoSuchBucket`, `NoSuchHost`, `HEROKU_NO_SUCH_APP`, "pages" lookup-failed, Zendesk/Sendgrid "doesn't exist"
- Passive DNS (crt.sh/wayback) shows records pointing to retired SaaS hosts · wildcard `*.domain` in zone
- Parent sets `Domain=.domain.com` cookies; SSO/CSP/redirect allowlists mention the sub

## Tools
- `subzy -target-list subs.txt` / `nuclei -tags takeover -l subs.txt` — triage only, verify by hand
- `dig +short FUZZ CNAME` loop; `host -t NS` for delegation checks
- `curl -sI http://SUB/` capture server banner/error body → match can-i-take-over-xyz fingerprint table
- crt.sh/certspotter for historical records: `curl -s 'https://crt.sh/?q=%25.SUB' | jq`