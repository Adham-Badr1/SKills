---
name: recon-infra
description: >-
  Infra probing — live-host detection, HTTP fingerprinting, port discovery, soft-404
  filtering, 403/405 bypass matrix, CDN/origin-IP hunting, vhost sweeps. Auto-invoke
  when: recon tier 2-3 runs, a new resolved host needs probing, 403/401/405 blocks,
  CDN WAF suspected. Do NOT load for: URL/param work on live hosts →
  `recon-endpoints`; claimable CNAMEs → `subdomain_takeover`.
family: sink-signal
severity: info
---

# Recon-Infra — probe · fingerprint · bypass · origin hunt

> **Arsenal:** alive hosts split by status, tech fingerprints, open ports, origin IPs
> behind CDNs, and bypassed 403/405 doors.
> **Sibling:** `recon-subdomains` (names in), `recon-endpoints` (content out),
> `access-control` (what the bypassed doors unlock), `recon-cloud` (cloud routing).
> **Proof bar:** ≥2 sources for a host being alive (httpx + banner); a bypass proven by
> CONTENT change (same 403 body = no bypass, never count status alone).
> **Setup:** subs.txt from recon-subdomains; rate limits honored.

## WAF Bypass (infra level)
- **403-bypass matrix (per path):** `/admin` → `/admin/` `/admin/.` `/admin/..;/` `/admin%2f` `/admin/*` `/./admin` `/%2e/admin` `/admin#` `/admin?` case-flip `/ADMIN` · headers `X-Original-URL` `X-Rewrite-URL` `X-Forwarded-For: 127.0.0.1` `X-Custom-IP-Authorization: 127.0.0.1` · method swap + `X-HTTP-Method-Override`/`_method=`
- **405 matrix:** GET↔POST↔PUT↔PATCH↔HEAD↔OPTIONS + overrides — record accepted verbs
- **CDN/origin:** find origin IP (historical DNS, SSL SANs, SPF, `dig -x` PTB sweep, cert transparency IP logs) → probe origin directly (WAF-less surface)
- **Vhost sweep:** `ffuf -w vhosts.txt -u https://ORIGIN/ -H "Host: FUZZ.$T"` behind shared IPs

## Context
- Probing separates live from dead and interesting from noise: status split (200/403/5xx),
  soft-404 filtering (same body any path), tech flags (jenkins/gitlab/grafana/kibana/jira/
  confluence/tomcat/phpmyadmin/swagger/graphql/actuator/.git/elasticsearch) → each interesting
  host routes to its owning skill.

## General Techniques
- **Alive check:** `httpx -ports 80,443,8080,8443,8000,3000,5000 -threads 200 -sc -cl -title -server -td -silent -o httpx.txt`
- **Splits:** 200_alive → content work; 403_alive → bypass matrix; 5xx → flag for later
- **Soft-404:** request random path — same body/length as 404 → mark noise
- **Port scan (authorized):** naabu `-top-ports 1000` / nmap on interesting hosts; banner→CVE
- **Screenshots (long):** gowitness/aquatone → visual triage of dashboards/logins
- **Tech fingerprint:** `httpx -td` / Wappalyzer / `whatweb` — banner → CVE queue (→ info_disclosure CVE table)
- **Method discovery:** OPTIONS on APIs → allowed verbs (→ api)
- **Cloud routing:** CNAME→cloud (→ recon-cloud); origin IP reallocation risk (→ subdomain_takeover)
- **Protocol edges:** HTTPS-only, HTTP→HTTPS redirect, `http://` origin responses (cookie leakage surfaces)

## Second-Order & Bypass Techniques
- Once origin IP found: re-run the 403 matrix against ORIGIN (no CDN WAF)
- Staging port on prod host (`:8080`, `:3000` dev dashboards)

## Auth Bypass Techniques
- 403/401 paths bypassed via the matrix → hidden admin/auth surfaces (→ access-control)
- `/actuator`, `/phpinfo.php`, `/server-status` answers = debug surface (→ info_disclosure)

## Header Techniques
- `Server`/`X-Powered-By`/`X-AspNet-Version` fingerprinting · `X-Original-URL`/`X-Rewrite-URL` proxies
- `X-Forwarded-*` trust probes on auth endpoints (gate-check before access-control)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-44228 | log4j stack banner | JNDI header RCE probe |
| CVE-2021-41773/42013 | Apache httpd 2.4.49/50 | path traversal RCE |
| CVE-2021-26855 (ProxyLogon) | Exchange 2013-2019 | SSRF auth bypass |
| CVE-2021-22986 | F5 BIG-IP | unauth API RCE |

## Indicators — record as `possible` when seen
- 200 on interesting tech (jenkins/grafana/actuator/phpmyadmin/swagger/git) → owning skill
- 403/401/405 on paths worth opening · `Server` banners with versions · origin IP ≠ CDN IP
- Vhost answering different content per Host header · dev ports on prod hosts

## Tools
- `httpx -l subs.txt -ports 80,443,8080,8443,3000,5000 -sc -cl -title -server -td -silent`
- `naabu -l alive.txt -top-ports 1000 -rate 200` (authorized only); `whatweb -a 3 URL`
- `ffuf -w paths.txt -u URL/FUZZ -mc all -fc 404 -t 50` for the 403 matrix
- nuclei `-tags tech,exposure` triage; verify every hit by hand with content diff