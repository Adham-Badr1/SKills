---
name: oauth
description: >-
  OAuth/OIDC attacks — redirect_uri validation bypass, state/CSRF, account linking,
  token theft via Referer/postMessage, client confusion, PKCE downgrade, dynamic
  registration, scope manipulation. Auto-invoke when: OAuth/OIDC/SAML flows,
  /authorize /token /callback endpoints, redirect_uri/state/code params, social login,
  `.well-known/openid-configuration`. Do NOT load for: raw JWT crypto → `jwt`; redirect
  params on plain login → `open_redirect`.
family: state-machine
severity: high → critical
---

# OAuth & OIDC — flows · redirect_uri · state · token theft

> **Arsenal:** steal authorization codes/tokens, hijack account linking, log in as
> victims via confused flows, mint tokens for other clients.
> **Sibling:** `jwt` (token crypto), `open_redirect` (redirect sinks), `csrf` (login CSRF),
> `account_takeover` (linking-into-ATO), `postmessage` (popup token messaging).
> **Proof bar:** the victim's authorization code/access token arrives at attacker, or an
> account link binds attacker identity to victim account, or token minted for client X
> accepted by client Y. State param missing alone = `possible` (needs the login-CSRF chain).
> **Setup:** register a client when dynamic registration is open; two social identities otherwise.

## WAF Bypass (OAuth)
- redirect_uri substring validation: `https://evil.com` vs `https://evil.com@trusted.com` (`@` trick), `https://trusted.com.evil.com`
- path-based allowlist escape: `redirect_uri=https://trusted.com/../evil` or `https://trusted.com/cb?x=//evil.com`
- Scheme-relative `//evil.com` · port/backslash confusion (`https://trusted\@evil.com`) · unicode dots (`.` fullwidth)
- Parser differential: `redirect_uri` validated by one parser, consumed by another (encoded `%2f`, fragments `#`)
- Same client_id reused cross-host; `redirect_uri` array params (last-wins)
- Fragment-based token delivery: token in `#` — capture via postMessage/Referer instead of code

## Context
- Four flows to know: authorization-code (server), implicit (fragment token), ROPC (password grant),
  client-credential (service). Bugs concentrate in: redirect_uri validation, state generation,
  linking without ownership proof, code single-use/expiry, PKCE optionality, scope enforcement.
- Always map: `/authorize` params → `/callback` handler → token exchange → app session creation.

## General Techniques
- **redirect_uri swap:** victim clicks your authorize URL with YOUR redirect_uri → code lands at attacker
- **state-less login CSRF:** no/weak state → force victim to authorize YOUR identity → their account binds attacker login
- **Account linking without verification:** OAuth login links email from provider WITHOUT proving ownership → attacker social-login victim's email → ATO
- **Client confusion:** token minted for client A presented to client B (implicit flow, shared token endpoint)
- **Code injection:** replay victim's code in your session (binding gap) — code not bound to client/session
- **Code reuse:** multi-use authorization codes
- **ROPC as 2FA bypass:** password-grant endpoint ignores MFA enforcement
- **PKCE downgrade:** strip `code_challenge` → exchange without verifier
- **Dynamic client registration:** register malicious client with PKCE capturing victim's redirected codes
- **Scope manipulation:** request `scope=admin` — server grants unregistered/elevated scopes, or displays misleading consent
- **open redirector on `.well-known` meta:** `OpenID.ConfigurationDiscovery` URLs user-controlled → phishing
- **Implicit token leak:** token in fragment + `postMessage` to opener without origin check (→ `postmessage`)
- **Referer theft:** token/`code` in URL — victim's page (with your HTML) logs Referer

## Second-Order & Bypass Techniques
- Login endpoint consumes BOTH OAuth and password — attacker-provided `state`/`email` reused across flows
- Existing link + new provider: adding attacker's Google to victim account when "already logged in" session is theirs (state garbled)
- Offline_access/refresh: steal refresh via dynamic client → persistent access

## Auth Bypass Techniques
- Pre-registered attacker client_url whitelisted (or open redirect on a whitelisted domain) → code capture
- `login_hint`-driven accounts: force victim into attacker's prepared session
- SAML/OIDC federation gap: accept unsigned/malleable assertions (→ `authentication`)

## Header Techniques
- `Origin`/`Referer` trusted for callback validation — spoof on authorizing host
- `Forwarded`/`X-Forwarded-Proto` changing the callback scheme (https→http downgrade)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-32836 | Keycloak < 18 | session fixation → ATO via state param |
| CVE-2020-27838 | Keycloak | client-registration auth bypass |
| CVE-2019-10194 | Keycloak 3.x–8.x | redirect_uri open redirect (ATO chain) |
| CVE-2018-16642 | Spring OAuth2 | token leakage via debug |

## Indicators — record as `possible` when seen
- `/authorize?response_type=code&client_id=...&redirect_uri=...&state=...` without state or with weak state (static/derived)
- Callback accepting unknown query params · login flow detects provider vs password social buttons
- `.well-known/openid-configuration` reachable; dynamic registration endpoint POSTs 201
- Tokens in fragment (`#access_token=`); postMessage from popup windows (→ postmessage skill)

## Tools
- Burp: intercept authorize flow, mutate redirect_uri/state/client_id; use Authorize-ish "flow walker"
- `oauth-pentester-framework` scripts; `ffuf` on redirect_uri variants (`-w uris.txt -u 'URL/authorize?...redirect_uri=FUZZ' -fr 'error'`)
- Browser devtools: capture postMessage payloads from provider popups
- `curl -s URL/.well-known/openid-configuration | jq '{authorization_endpoint, token_endpoint, registration_endpoint}'`