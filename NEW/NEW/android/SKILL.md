---
name: android
description: >-
  Android/mobile app testing — APK analysis, insecure storage, exported components,
  webview bridges, deep-link hijack, Firebase/cloud misconfig, cert-pinning bypass,
  cleartext traffic, backup extraction, tapjacking. Auto-invoke when: APK/IPA files,
  mobile API endpoints, deeplink schemes (app://), Firebase/Appwrite/Supabase keys in
  app assets, mobile-only endpoints in JS bundles. Do NOT load for: plain web APIs →
  `api`; webview-rendered content → `xss`.
family: sink-signal
severity: medium → critical
---

# Android — APK · webview · storage · deeplinks · mobile APIs

> **Arsenal:** extract secrets/keys from apps, call mobile APIs with crafted authz,
> hijack deeplinks, read app data via backups, bypass pinning to intercept.
> **Sibling:** `api` (mobile endpoints), `file_upload` (app-driven uploads),
> `cloud_iam_privesc` (Firebase/Supabase keys), `xss` (webview content).
> **Proof bar:** an app-internal secret/session usable against the backend, or a
> deeplink/firebase/webview primitive demonstrated (state change/data read).
> APK presence alone = `possible`.
> **Setup:** APK/IPA from the store/client; adb + emulator/physical device; Frida or
> objection for dynamic work.

## WAF Bypass (mobile — the "WAF" is cert pinning & obfuscation)
- Cert-pinning bypass: Frida `frida-ios-hook`/`objection android sslpinning disable` or `frida -f app -l ssl-pinning.js`
- Obfuscation: dex decompile (jadx) then re-read; strings in native libs (`strings lib.so | grep -i secret`)
- Cleartext flag: `android:usesCleartextTraffic="true"` → HTTP API endpoints sniffable on shared wifi
- Backup data: `adb backup -f app.ab` (allowBackup=true) → `abe.jar` extract → tokens/session

## Context
- Mobile bugs = the app's PRIVILEGE RELATIONSHIPS: what the app trusts (stored keys, deeplink
  intents, webview bridge), what it exposes (exported components, backup, clipboard), and how it
  authenticates (mobile API tokens, Firebase rules). Test the APP first (static), then its APIs
  with web-tooling (Burp).

## General Techniques
- **Insecure storage:** SharedPreferences/Realm/SQLite with tokens/keys — read via `run-as`/`adb shell`
- **Hardcoded secrets:** API keys, Firebase config, Supabase anon keys in assets/strings — validate (→ `recon-secrets`)
- **Webview addJavascriptInterface:** bridge method → file read/RCE if untrusted content rendered
- **Exported activities:** `android:exported="true"` + no permission → invoke from another app (auth bypass, data flow)
- **Deep-link hijack:** scheme handler takes `url`/`token` params → craft malicious link → token capture/state change
- **Backup extraction (allowBackup):** `adb backup` → app data with sessions → replay on API
- **Cleartext traffic:** HTTP endpoints in-scope — sniff/redirect (MITM) on test device
- **Debuggable prod build:** `run-as` file read, memory inspect, debugger attach
- **Firebase/Firestore misconfig:** anon key + rules `"read": true` → full DB read/write (→ `cloud_iam_privesc`)
- **Mobile API authz:** endpoints callable without the app (Burp) — same classes as `api`
- **Clipboard leak:** secrets copied to clipboard readable by other apps (Android 10-)
- **Tapjacking:** overlay blinds the user into confirming privileged actions
- **Root-detection bypass:** Frida hook `/data/local/tmp` + Magisk DenyList — for DEEPER app access
- **Tampering/repackaging:** weak signer (SHA1withRSA/debug cert/Janus v1) → modified APK accepted by backend
- **Weak crypto:** ECB/AES with static key in assets → decrypt app traffic/config

## Second-Order & Bypass Techniques
- Stolen token from backup replayed later (no device binding); device-bound tokens → clone device IDs
- In-app update: insecure update mechanism → tampered APK delivery → RCE on install (→ `supply_chain`)

## Auth Bypass Techniques
- Firebase rules auth bypass: `"rules": {".read": true}` on user data; Supabase RLS missing
- Deeplink-driven login: handler skips auth for `app://login?token=...` — forge token

## Header Techniques
- Mobile app User-Agents/tokens accepted without origin checks; API `X-Api-Key` from app = static
- Cert-pinning enforcement per-endpoint: some endpoints unpinned (Burp intercept those)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-21311 | H2 web console (adjacent) | (rare app-specific CVEs — search per app) |
| CVE-2023-26611 | CVE-2023-26611 | exported-component authz (family) |
| CVE-2019-5475 | (deeplink family) | scheme hijack chain demo |

## Indicators — record as `possible` when seen
- APK/IPA in scope · Firebase URL + anon key in assets · deeplink schemes in strings.xml
- `allowBackup=true`, `usesCleartextTraffic=true`, `debuggable=true` in manifest
- addJavascriptInterface bridge names in decompiled code · exported components in manifest
- App-only API endpoints (mobile UA-only, missing on web)

## Tools
- `jadx -d out app.apk` (decompile); `apktool d` (resources/manifest)
- `adb backup -f app.ab && abe unpack app.ab` (extract); `adb shell run-as <pkg> ls shared_prefs`
- Frida: `frida -U -f <pkg> -l ssl-pinning.js` (objection too); `adb logcat` for key logging
- Burp on emulator (`adb reverse tcp:8080 tcp:8080` + proxy) for API testing; `strings lib/*.so`