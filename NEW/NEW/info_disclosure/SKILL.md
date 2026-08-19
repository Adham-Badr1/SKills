---
name: info_disclosure
description: >-
  Information disclosure — debug endpoints, verbose errors/stack traces, source maps,
  .git exposure, backups/configs, directory listing, swagger, version banners,
  hardcoded secrets in comments/JS. Auto-invoke when: stack traces/actuator/phpinfo/
  __debug__-style pages, .js.map/sourceMappingURL, .env/.git/.bak files, verbose error
  text, version banners. Do NOT load for: secret-file validation → `recon-secrets`;
  JS endpoint harvesting → `recon-js`.
family: sink-signal
severity: low → high
---

# Info Disclosure — leaks → recon enrichment → exploit fuel

> **Arsenal:** internal paths, versions, secrets, and debug surfaces that turn `possible`
> into confirmed chains.
> **Sibling:** `recon-secrets` (validating leaked keys), `recon-js` (bundle mining),
> `file_upload` (error-path leaks), `api` (debug handlers).
> **Proof bar:** a NON-PUBLIC datum confirmed from the target (internal host/IP, source,
> key material, backup content, admin path). Version banners alone = `possible`.
> **Setup:** none — passive probing; content discovery feeds this skill.

## WAF Bypass (disclosure — the "bypass" is path fuzzing)
- Extension rotation: `index.php.bak`, `index.php~`, `index.php.swp`, `%2e%2e/` traversal reads
- Verbose-error toggling: add `?debug=1`, `?test=1`, `X-Debug: true` headers — some apps flip verbosity
- HTTP vs HTTPS: some debug endpoints only on one scheme/port (`:8080`, `:8443`)
- Version hidden: `X-Powered-By`/`Server`/cookies/banner order → CVE mapping (→ CVE table)
- Error trigger: malformed request → stack trace with paths, DB creds, internals

## Context
- Disclosure is the ENRICHER: it doesn't need a sink, it needs the app to leak what it
  shouldn't. Sources: error handlers, debug flags, backup jobs, build artifacts (.git, .map),
  framework endpoints (actuator, phpinfo, __debug__), directory listing, verbose logs,
  swagger leftovers, analytics IDs.

## General Techniques
- **Stack traces:** malformed input → full path/version/DB name in trace
- **Debug endpoints:** `/actuator/*` (Spring: env, heapdump, mappings, health details), `/phpinfo.php`, `__debug__`, `/server-status`, `/status`, `/metrics`
- **Source maps:** `.js.map` + `sourceMappingURL` → reconstruct source → route tables, hardcoded keys (→ `recon-js`)
- **.git exposure:** `/ .git/config` → `git-dumper` full history → secrets in deleted files
- **Backups:** `.bak` `.old` `.swp` `.tar.gz` `.zip` `db.sql` `config.php.bak` `wp-config.php.bak` `backup.sql` in roots
- **Directory listing:** open dirs → internal file inventory (logs, configs, uploads)
- **Swagger/OpenAPI leftovers:** `/swagger.json`, `/v3/api-docs`, `/redoc`, `/api/schema` (→ `api`)
- **Version banners:** `Server: nginx/1.24`, cookie/error/header fingerprints → CVE table lookup
- **Internal host leaks:** error emails/messages with `10.x.x.x`, `db01.internal`, SMTP hostnames
- **Config exposure:** `.env` readable, `config/` dirs, `application.yml`, `web.config` with secrets
- **Metadata leaks:** EXIF GPS in uploads, PDF metadata with usernames/paths, file timestamps
- **Hardcoded secrets in comments/JS:** `TODO: fix key`, `api_key =`, `password:` in bundle comments (→ `recon-secrets`)
- **Excessive data exposure:** API responses with password hashes/OTP/tokens (→ `api`)
- **Verbose errors:** 500s with SQL/user names → enumeration oracles (→ `sqli`)

## Second-Order & Bypass Techniques
- Error text on a SECOND endpoint references the FIRST's internals (cross-app leak)
- Debug endpoint enabled in staging only — probe staging hosts (→ `recon-infra`)

## Auth Bypass Techniques
- `/actuator/env` / `/actuator/heapdump` → secrets → credential-driven auth bypass (→ `recon-secrets`)
- Debug login pages (`/dev/login`, `?bypass=1`) left in prod

## Header Techniques
- `X-Powered-By`, `Server`, `X-Generator`, `X-AspNet-Version` — stack fingerprinting
- `X-Debug`, `X-StackTrace`, `X-Internal`, `Debug: true` request headers flipping verbosity

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-21234 | Spring Boot actuator | logfile disclosure → RCE chain |
| CVE-2022-22963/22965 | Spring Cloud/Spring4Shell | actuator-adjacent chains |
| CVE-2019-10758 | mongo-express | config leak + RCE |
| CVE-2020-13945 | Apache APISIX | admin API disclosure |

## Indicators — record as `possible` when seen
- Stack traces, absolute paths, DB names in error bodies · `.js.map`/`sourceMappingURL` references
- `.git/`, `/.env`, `*.bak`, `db.sql`, `backup.zip` in fuzz results · directory listings
- `/actuator`, `/phpinfo.php`, `__debug__`, `/server-status` answers · swagger/api-docs paths 200
- Version strings in headers/cookies/errors · internal IPs/hostnames in any text

## Tools
- `ffuf -w content-lists.txt -u URL/FUZZ -mc 200,301,403` (recon-endpoints content tier)
- `git-dumper URL/.git/ out/ && git log -p --all | grep -iE 'key|secret|password'`
- `curl -s URL/actuator/env | jq '.propertySources[].properties | keys'`
- nuclei `-tags exposure,config,debug` for triage; verify every 200 by hand