---
name: recon-subdomains
description: >-
  Subdomain enumeration — passive (CT, sources) + active (brute, permutation,
  wildcard) discovery, resolution, dedup, and candidate handoff. Auto-invoke when:
  recon tier 1 runs, new apex added, subfinder/dnsx/ffuf-dns outputs need folding in.
  Do NOT load for: claiming dangling CNAMEs → `subdomain_takeover`; IP-level infra →
  `recon-infra`.
family: sink-signal
severity: info
---

# Recon-Subdomains — enumeration → resolution → candidates

> **Arsenal:** the complete subdomain list (subs.txt), resolved alive set, and takeover
> candidates.
> **Sibling:** `subdomain_takeover` (claimable CNAMEs), `recon-infra` (live-host
> probing), `recon-osint` (feeds), `recon-cloud` (cloud CNAME routing).
> **Proof bar:** every name in subs.txt is real (resolution/CT-verified); candidates for
> takeover flagged separately — never merged into generic lists.
> **Setup:** apex confirmed in-scope; watchdogs on slow resolvers.

## WAF Bypass (enumeration — the gates are rate limits & wildcards)
- Wildcard detection FIRST: resolve `random-<hex>.domain.com` — if it resolves, wildcard present → dedupe logic must handle
- Rate limits: subfinder -all, dnsx -t 150, puredns rate-capped; back off on NXDOMAIN floods (some DNS resolvers throttle)
- crt.sh 502/HTML: validate JSON before jq, retry with backoff, use certspotter/OTX as fallback

## Context
- Passive first (zero packets), then active brute/permutation. Resolution separates real from
  phantom; alive-check (→ recon-infra) separates live from dead. Every new name mid-hunt re-enters
  the loop once.

## General Techniques
- **Passive:** `subfinder -d $T -all -recursive -silent` · `assetfinder --subs-only` · `findomain -t -q` · `chaos -d` · crt.sh · OTX/HackerTarget/URLScan/VirusTotal · github-subdomains
- **Active brute (long):** `ffuf -u https://FUZZ.$T -w dns-wordlist -mc 200,301,302,403` or puredns/massdns with `-t 1000 --rate 10000`
- **Permutation (long):** `alterx -l subs.txt` → `dnsx -silent` → resolve; `gotator` for combo names
- **Resolution:** `dnsx -l subs.txt -silent -a -cname -resp-only` → alive set + CNAME map
- **CNAME map:** `dnsx -cname` output → cloud-service CNAMEs (→ recon-cloud, subdomain_takeover)
- **Dedup:** `anew` between runs — subs.new feeds probing; status is the dedup (→ ledger)
- **Zone-walk/axfr (rare):** `dig axfr @ns domain.com` — misconfigured zone transfers (record, low sev)
- **Third-level depth:** subfinder -recursive; `./subs` → `sub.subs` permutations of interesting subs

## Second-Order & Bypass Techniques
- Historical names: passive DNS + wayback → REMOVED subdomains (still resolvable? old infra alive?)
- Wildcard-aware per-host probing: append each resolved IP — vhost confusion sweep (→ recon-infra)

## Auth Bypass Techniques
- (n/a — discovery tier)

## Header Techniques
- (n/a — DNS tier; header probing in recon-infra)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (enumeration finds the surface; CVEs fire in the owning skill) | — | — |

## Indicators — record as `possible` when seen
- CNAME → NXDOMAIN / cloud-service hostname (takeover candidate → subdomain_takeover)
- Subdomain with different tech/ports (interesting → recon-infra)
- Wildcard record present · historical subdomains still resolving · zone-transferable zones

## Tools
- `subfinder -d $T -all -silent -o subs_raw.txt` · `dnsx -l subs.txt -silent -a -cname -o resolved.txt`
- `alterx -l subs.txt | dnsx -silent -resp-only` (permutation pass)
- `curl -s 'https://crt.sh/?q=%25.$T&output=json' | jq -r '.[].name_value' | sort -u` (with backoff)
- `anew` for dedup; `dig axfr @<ns> $T` spot-check