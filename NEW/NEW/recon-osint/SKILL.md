---
name: recon-osint
description: >-
  OSINT recon tier — passive footprint before packets: ASN/CIDR, emails, tech, GitHub
  leaks, passive DNS, CT logs, doc metadata, analytics pivots. Auto-invoke when:
  recon tier 0-1 runs, new company/domain scope, scope expansion, passive-attribution
  needed. Do NOT load for: full-scope OSINT reporting → `osint`; live scanning →
  `recon-infra`.
family: sink-signal
severity: info
---

# Recon-OSINT — passive footprint → scope + attack seeds

> **Arsenal:** org footprint (ASNs, CIDRs, emails, tech stack, co-owned domains, GitHub
> hits) — everything later tiers validate.
> **Sibling:** `osint` (deep-dive skill, same source family — use it for the OSINT
> REPORT; this tier feeds recon), `recon-subdomains` (names), `recon-infra` (IPs).
> **Proof bar:** ≥2 independent sources for any claimed asset (CT + passive DNS +
> search) — single-source hits are candidates. Emails/breach-correlation only used
> client-approved.
> **Setup:** none — zero-touch.

## WAF Bypass (OSINT)
- Rate-limited sources (crt.sh 502s, GitHub search) → retry with backoff, alternate sources, direct API URLs
- Search-engine blocks → `site:` operator variants, Bing/DuckDuckGo rotation, archive.org cached copies
- CT-log APIs: crt.sh vs certspotter vs censys — union them (each has different coverage)

## Context
- OSINT widens scope SAFELY: co-owned domains, staging hosts, vendors — the active tiers then
  hit what's in-scope. Never touch anything not confirmed in-scope; record `possible` for the rest.

## General Techniques
- **CT logs:** `curl -s 'https://crt.sh/?q=%25.domain&output=json' | jq -r '.[].name_value'` → cert-subdomains (→ recon-subdomains)
- **ASN/CIDR:** `amass intel -org <name> -asn -cidr` · `asnmap -d domain` (confirm in-scope before touching)
- **Passive DNS:** SecurityTrails/OTX/VirusTotal — old IPs, vhosts, co-hosted domains
- **Emails:** theHarvester, hunter.io, GitHub code search `@domain.com` — seed for enumeration
- **GitHub:** `gh search code "domain.com"` / org repos → secrets, internal tool names (→ supply_chain/recon-secrets)
- **Wayback CDX:** `curl 'https://web.archive.org/cdx/search/cdx?url=*.domain.com/*&output=json&fl=original'` → historical URLs (→ recon-endpoints)
- **Tech fingerprint (passive):** Wappalyzer-style banners, `dns.google` TXT/SPF (mail infra), SSL SANs
- **Doc metadata:** Google dork `filetype:pdf site:domain.com` → EXIF/authors/paths
- **Analytics IDs:** UA-/G-/GTM- IDs on target pages → Shodan/FOFA/PublicWWW → co-owned domains
- **Breach-correlation:** emails → haveibeenpwned-style check (client-approved credential-reuse tests only)

## Second-Order & Bypass Techniques
- Vendor SaaS instances discovered (Zendesk/Sendgrid/Atlassian hosts) → third-party trust surface (→ supply_chain)
- Staging/dev hostnames in public docs → separate mini-scope (in-scope only)

## Auth Bypass Techniques
- (passive — auth probing happens in later tiers)

## Header Techniques
- SPF/DMARC TXT records → mail providers/SES/security scanners; certificate SANs = host inventory

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (fingerprint-then-map — banner → CVE in the owning skill) | — | — |

## Indicators — record as `possible` when seen
- Cert SANs beyond known subs · ASN/CIDR blocks owned by org · emails + breach-dump presence
- GitHub repos/tool names · staging/vendor hosts · analytics IDs → co-owned domains
- Old IPs in passive DNS (cloud reallocation risk → recon-cloud)

## Tools
- `curl -s 'https://crt.sh/?q=%25.domain&output=json' | jq -r '.[].name_value' | sort -u`
- theHarvester (`-b all`), amass intel, asnmap, wayback CDX curl
- `gh search code "domain.com"` (rate-limit aware); `dig +short TXT domain.com`
- Shodan/Censys/FOFA web UI — no API key for basic attribution