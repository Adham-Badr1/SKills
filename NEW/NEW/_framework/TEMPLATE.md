# Skill Template — how to build any SKILL.md

Every skill lives in its own folder as ONE file: `<skill>/SKILL.md`. Max **120 lines** —
hard cap. The model loads it on trigger, uses it, unloads it. Keep every section of this
template in this exact order. Copy this file, fill the sections, delete what does not apply.
Do NOT add python to skills — commands are bash/curl only. Verification = `curl -s ... -o f -w "%{http_code}"` + bash `exit 0/2` scripts (allowed, they are a TOOL).

---

```markdown
---
name: <skill-slug>                       # folder name, kebab-case
description: >-
  <ONE line: what it finds + the impact it delivers.>
  Auto-invoke when: <exact signals — params, headers, response strings, JS sinks>.
  Do NOT load for: <sibling classes → name the skill to hand off to>.
family: differential|sink-signal|state-machine     # proof shape (pick one; see below)
severity: low|medium|high|critical                 # max realistic impact of the class
---

# <Title> — <arsenal one-liner: what primitives you walk away with>

> **Arsenal:** <one line: the primitives this skill yields>. **Sibling:** <what overlaps
> and the class boundary — e.g. "reflected input → `xss`; JSON filter keys → `nosqli`".>
> **Proof bar:** <one line: what counts as confirmed for THIS class — cross-account leak,
> state change, OOB callback, timing delta>.
> **Setup contract (if two accounts A/B needed):** reference `ledger/cookies_session.json`.

## WAF Bypass <mechanism for THIS vuln class>
- <the filter that commonly blocks, and the encoding/context trick that defeats it>
- <case/whitespace/encoding/parser-differential variants — max 4 bullets>

## Context <when this vuln is even reachable>
- <what the app must be doing for this sink to exist — 2–4 bullets>
- <what the parent ledger signal looked like when you were routed here>

## General Techniques
- **<technique>:** <one-line how + the observable to look for>
- (5–15 bullets; each one self-contained, no nested sub-lists)

## Second-Order & Bypass Techniques
- <stored-payload → fires at a later sink; list the trigger pairs>
- <filter-perimeter edge cases that defeat whitelists>

## Auth Bypass Techniques
- <login/reset/session-context tricks specific to this class — may be "n/a → see authentication">

## Header Techniques
- <headers that carry this vuln / that bypass this class's gates>

## CVE on Sight
| CVE | Surface | Class |
|-----|---------|-------|
| CVE-XXXX-XXXXX | <tech/endpoint that reveals it> | <families> |

## Indicators — record as `possible` when seen
- <signal → what it implies>
- (every response must yield ≥1 signal; if none, re-read the response)

## Tools
- <tool / one-liner commands — bash only>
```

## Section role map (why this order)

| Order | Section | Why |
|---|---|---|
| frontmatter | `name/description/family/severity` | the auto-invoke contract — the global prompt's trigger table reads only `description` |
| title | arsenal + siblings + proof bar | orientation in 3 lines; sibling pointer prevents loading two skills for one bug |
| WAF Bypass | per-class filter escape | comes first because every probe after it assumes the bypass works |
| Context | reachability & setup | the IF of the vuln — nothing below applies without it |
| General Techniques | the technique list | the meat; each bullet one request-pair idea |
| Second-Order & Bypass | stored/replayed variants | the tail that double-bounces filters |
| Auth Bypass | login/session context | the highest-impact instantiation of most classes |
| Header Techniques | header-carried variants | cheap + often missed |
| CVE on Sight | version → CVE | turn banners into grounded exploit attempts |
| Indicators | `possible`-lead triggers | fed straight into `ledger/*.json` |
| Tools | commands | bash/curl only — no embedded python |

## Family definitions (proof shape — drives APEX's proof bar)

- **differential** — proof = stable measurable delta between two arms (boolean, timing ≥3
  repeats, content-length). Use for sqli, nosqli, xss, ssrf, ssti, lfi, idor-style tests.
- **sink-signal** — proof = an OBSERVABLE effect on a sink (OOB callback, error echo,
  rendered value). Use for rce, deserialization, ssrf-OAST, file_upload, graphql, postmessage.
- **state-machine** — proof = an observed STATE CHANGE (role flipped, balance moved, 2FA
  skipped). Use for business-logic, race_condition, access-control escalations, mfa, csrf.

## Hard rules

1. **≤120 lines.** If a section would overflow, cut details — never cut sections.
2. **No python in skills.** Bash/curl commands and exit-code scripts only.
3. **No factory jargon** — the global prompt (APEX-HUNTER.md) owns workspace
   mechanics; skills own techniques.
4. **Sibling pointers appear twice:** in frontmatter `Do NOT load for:` and in the arsenal
   line. This is what keeps one bug loaded into exactly one skill.
5. **One file per skill folder.** No METHODOLOGY-REFERENCE.md, no extra docs.
6. Split a skill when it exceeds 120 lines: create `<skill>-<sub>` folders (e.g.
   `recon-js`, `nosqli`) and have the parent skill route to them. Never exceed the cap.