---
name: supply_chain
description: >-
  Supply-chain compromise — hardcoded secrets in repos, dependency confusion,
  typosquatting, install-hook execution, package-ownership takeover, CI/CD pipeline
  compromise, SLSA gaps, trojanized updates, manifest confusion. Auto-invoke when:
  hardcoded keys/secrets in code/repos, private package names, CI/CD configs, lockfiles
  with untrusted deps, build environments. Do NOT load for: generic cloud keys →
  `recon-secrets`/`cloud_iam_privesc`; pure OSINT → `osint`.
family: sink-signal
severity: high → critical
---

# Supply Chain — repo secrets · deps · packages · CI/CD

> **Arsenal:** turn a leaked repo secret into pipeline/package compromise; hijack
> dependency resolution to execute code at install/import time.
> **Sibling:** `recon-secrets` (validation), `cloud_iam_privesc` (cloud keys),
> `osint` (GitHub discovery), `rce` (executed payloads).
> **Proof bar:** a leaked secret VALIDATED against the provider (token works), or a
> dependency-confusion/typosquat condition DEMONSTRATED (name resolves to attacker
> package — publish only to YOUR test registry), or CI installs attacker package.
> Presence-of-secret without validation = `possible`.
> **Setup:** GitHub/registry access for reading (public); publishing tests ONLY on your
> own registry/package names.

## WAF Bypass (supply chain — the "WAF" is code review & secret scanners)
- Git history archaeology: secrets in DELETED commits (`git log -p`, `--all`, stale forks/branches)
- Comments/docs/paste-style leaks: `TODO: fix`, `FIXME secret`, README config examples with real keys
- Lockfile/CI artifacts: `.npmrc`, `~/.aws/credentials` commits, env templates, docker layers
- Tarball manifests: package-lock/yarn.lock metadata carries registry URLs — private-registry names leak
- GitHub search bypass: search engines (`site:github.com "domain" "secret"`) when API quota/rate-limited

## Context
- Supply-chain bugs = TRUST RELATIONSHIPS: code trusts env secrets, packages trust registry
  names, CI trusts commits, installers trust distribution channels. Find where attacker-
  controllable input meets trusted execution: package name resolution, install scripts,
  build agents, update channels.

## General Techniques
- **Hardcoded secret → pipeline:** repo token → CI pipeline variables/cache → full build env
- **Dependency confusion:** private package name NOT on public registry → publish SAME name with higher version on npm/PyPI/Gem → CI/installs pick yours (publish to YOUR OWN registry for proof)
- **Typosquat/namesquat:** lookalike names (`requests`, `requessts`) published to the registry — install-hook execution
- **Install-time hook execution:** malicious `postinstall`/`setup.py`/`.gemspec` — code runs at INSTALL, not import
- **Package-ownership takeover:** expired/claimable owner email on a package (DepFuzzer pattern) → publish malicious version
- **SLSA/provenance gap:** unsigned/unverified artifacts accepted by consumers → MITM binary swap
- **Build-environment attack:** cache poisoning, privileged build account, untrusted-branch builds
- **Trojanized update/installer:** the legitimate update channel compromised — ship malware through it
- **CI/CD pipeline compromise:** stolen build credentials → trojanize the build tool itself
- **Handler mapping abuse:** backend response triggers local handler execution in frontend server
- **Malicious archive/plugin/save-file:** attacker-chosen extensions inside imported files (→ `file_upload`)
- **npx binary-to-package confusion:** unclaimed binary name executed via `npx`
- **DLL hijacking:** untrusted search path — plant malicious DLL in app search order
- **Manifest confusion:** npm manifest/tarball mismatch hiding install scripts
- **Vulnerable components:** bundled JS/CSS/infra with known CVEs (→ CVE table of the component)

## Second-Order & Bypass Techniques
- Secret used in TWO contexts: repo token valid for CI AND cloud — pivot after first validation
- Package in one app's lockfile pulled by ANOTHER via monorepo — single poisoned dep spreads

## Auth Bypass Techniques
- CI machine tokens with wide scopes (read+write packages, secrets) → mint deploy credentials
- Package manager's `--registry` flag honoring malicious `~/.npmrc` in the project dir

## Header Techniques
- npm/PyPI/Gem auth headers in CI logs (leaked `_authToken`) · docker registry auth leaked in build logs

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2018-16486 | event-stream (npm) | trojanized package — THE classic |
| CVE-2022-25881 | http-cache-semantics | malicious package family |
| CVE-2023-2704 / 2705 | WP plugin family | supply-chain upload vector |
| CVE-2021-34558 | crypto-js (rare) | npm impersonation (family) |

## Indicators — record as `possible` when seen
- Hardcoded tokens/keys in public code · private package names absent from public registry
- CI configs referencing secrets without masking · install scripts in deps (`postinstall`)
- Lockfiles with registry URLs/owner emails · update/upgrade channels without signatures
- Unclaimed/expired email on a package owner record (OSV/registry API)

## Tools
- GitHub code search: `gh search code "domain.com" --limit 50` (or web); `git log -p --all | grep -i secret` on cloned repos
- Registry check: `npm view <name> time` / PyPI JSON API `curl -s https://pypi.org/pypi/<name>/json | jq '.info'`
- `osv-scanner -r .` / `pip-audit` for vulnerable components; `trufflehog`/`gitleaks` on repos
- `npm view <pkg> dist-tags` + `npm pack --dry-run` for manifest confusion review (read-only)