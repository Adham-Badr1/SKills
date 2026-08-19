---
name: osint
description: >-
  OSINT for web targets — passive footprint, emails, employees, tech, leaks, GitHub,
  cloud assets, social/paste pivots before touching the target. Auto-invoke when:
  engagement starts (new company/domain), you need scope expansion, leaked-cred/email
  discovery, tech-stack fingerprinting, asset attribution. Do NOT load for: live
  scanning/probing → `recon-infra`/`recon-subdomains`.
family: sink-signal
severity: info → medium
---

# OSINT — passive footprint → attack-surface seeding

> **Arsenal:** emails/employees, tech stack, leaked credentials, GitHub/cloud assets,
> co-owned domains, docs — everything recon will later validate actively.
> **Sibling:** `recon-osint` (orchestrated OSINT tier), `recon-subdomains` (names),
> `recon-cloud` (cloud assets), `supply_chain` (repo secrets).
> **Proof bar:** a NON-PUBLIC or newly-correlated datum (email in a breach dump tied to
> this org, private repo mention, internal tool name in a paste). Search results alone
> are fuel, not findings.
> **Setup:** none — all passive; respect TOS of each source; no login/paid sources without
> the client's OK.

## WAF Bypass (OSINT — no WAF; the limits are source TOS and rate limits)
- Search engines: operator fuzzing (`site:`, `inurl:`, `intitle:`, `filetype:`) — Google/Bing/DuckDuckGo
- Social-engineered search via public engines (Shodan/FOFA/Censys/Criminal IP) — no creds needed for the basics
- Cached/archive versions: Wayback Machine for removed content (`*domain.com/*` CDX queries)
- Git history as archive: forks/stale branches keep deleted secrets (→ `supply_chain`)

## Context
- OSINT runs FIRST, before a single packet. Output feeds: subdomain lists, email corpora for
  enumeration, tech fingerprint for CVE mapping, employee names for credential sprays (client-
  approved only), and scope decisions (what's in/out).

## General Techniques
- **Domain/asset correlation:** crt.sh/certspotter/CT logs → domains+subdomains (→ `recon-subdomains`)
- **Email harvesting:** hunter.io, theHarvester, search `@domain.com` — validate against scope
- **Breach-correlation:** email → haveibeenpwned/hashes (client-approved credential reuse testing)
- **Tech fingerprint:** Wappalyzer, HTTPSEverywhere banners, `dns.google` TXT/SPF (mail infra → security tools)
- **GitHub search:** `org:<name>`, `domain.com in:code`, code search for keys/filenames (→ `supply_chain`)
- **Paste/leak platforms:** GitHub gists, pastebin search for domain mentions
- **Document metadata:** Google dork `filetype:pdf site:domain.com` → EXIF/authors/paths (→ `info_disclosure`)
- **Cloud asset attribution:** S3 bucket names, cloud provider regions, DNS CNAMEs to cloud (→ `recon-cloud`)
- **Employee footprint:** LinkedIn/company pages → usernames for enumeration (authorized scope only)
- **Social media:** company posts leak tool names/vendors/versions — instant CVE fuel
- **Wayback CDX:** historical endpoints/URLs (→ `recon-endpoints`)
- **Shodan/Censys:** server banners, exposed services, SSL SANs — passive before any scan
- **DNS history:** SecurityTrails/OTX passive DNS → old IPs/vhosts (→ `recon-infra`)
- **Ads/analytics IDs:** UA-/G-/GTM- IDs → co-owned domains (→ `recon-*` pivots)

## Second-Order & Bypass Techniques
- Vendor-supply mapping: the org's SaaS vendors (Zendesk, Sendgrid, Cloudflare) → attack surface on THIRD-party trust (→ `supply_chain`)
- Employee's personal repos posting company code → internal tool names → targeted fuzz lists

## Auth Bypass Techniques
- Leaked creds from breach data → client-approved password reuse check on the org's SSO
- Staging/dev environments discoverable via search (→ `recon-infra`)

## Header Techniques
- SSL certificate SANs (crt.sh, censys) = host inventory; SPF/DMARC records reveal mail providers

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (OSINT → CVEs arrive via tech fingerprint) | banner → CVE | map after fingerprint |

## Indicators — record as `possible` when seen
- Emails tied to org + breach-dump presence · private-repo hits · internal tool/software names in public posts
- Cloud CNAMEs, S3 buckets, staging hostnames · old IPs in passive DNS · vendor SaaS instances (Zendesk=zendesk.com host)
- Docs/PDFs with author metadata/paths · analytics IDs correlating co-owned domains

## Tools
- theHarvester, hunter.io (limited), `curl 'https://crt.sh/?q=%25.domain&output=json' | jq`
- GitHub code search (via `gh api` on YOUR token, unauthenticated search limited)
- Wayback CDX: `curl 'https://web.archive.org/cdx/search/cdx?url=*.domain.com/*&output=json&fl=original'`
- Shodan/Censys web UI (no API key for basic); SPF: `dig +short TXT domain.com`
- theHarvester one-shot: `theHarvester -d domain.com -b all` (respect rate limits)