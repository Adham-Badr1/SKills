# Master Index — skills registry + auto-invoke trigger table + chains

One place that connects every `SKILL.md`. APEX-HUNTER.md (§Trigger Table) mirrors the
SIGNAL column; this file is the source of truth for what each skill loads on.

## Skill registry (folder → what it owns)

| Skill | Owns | Siblings it routes to |
|---|---|---|
| access-control | IDOR/BOLA/BFLA/BOPLA, privesc, revocation gaps | mfa, api, jwt |
| account_takeover | reset/email-change/magic-link/OTP ATO chains | authentication, oauth, csrf |
| android | mobile app surface, webview, backup, deep links | api, file_upload |
| api | REST/authz/versioning/header trust/rate limits | access-control, jwt, graphql |
| authentication | login, sessions, SAML/SSO, enumeration, rate-limit | account_takeover, mfa |
| business-logic | price/coupon/state-machine/payment abuse | race_condition, mfa |
| cloud_iam_privesc | AWS/GCP/Azure IAM escalation | ssrf, supply_chain |
| cors | ACAO/origin validation/preflight gaps | xss, postmessage |
| csrf | token/origin/method-verb gaps | oauth, graphql |
| deserialization | pickle/php/java/.net gadgets, ViewState, Flight | rce, file_upload |
| file_upload | webshell, traversal write, parser RCE, stored XSS | rce, ssrf |
| graphql | introspection, authz via resolvers, aliases, batching | api |
| info_disclosure | debug/backup/.git/maps/secrets leaks | recon-secrets, recon-js |
| jwt | alg confusion, none, brute, jku/kid, refresh | authentication, oauth |
| llm_prompt_injection | chat/RAG/agent injection, exfil, tool abuse | xss, business-logic |
| mfa | 2FA/OTP/TOTP/passkey enforcement gaps | authentication, access-control |
| nosqli | NoSQL operator/syntax/regex/aggregation injection | sqli |
| oauth | OAuth/OIDC flows, redirect_uri, state, token abuse | open_redirect, jwt |
| open_redirect | redirect param/host/parser bypasses | oauth, ssrf |
| osint | passive footprint, emails, leaks, pivots | recon-osint |
| postmessage | message listeners, origin validation, token theft | xss, cors |
| race_condition | TOCTOU, double-spend, rate-limit races | business-logic |
| rce | command/file-write/template/XXE→RCE chains | file_upload, deserialization, ssti |
| recon | orchestration: order, ledger feeding, handoff | recon-* (8 sub-skills) |
| recon-subdomains | passive+active subdomain discovery, resolution | subdomain_takeover |
| recon-osint | ASN/CIDR/emails/leaks/pivots before packets | recon-subdomains |
| recon-infra | probing, fingerprinting, ports, 403/405 matrix | recon-endpoints |
| recon-endpoints | URL history, params, content discovery, swagger | recon-js, recon-secrets |
| recon-js | JS bundles: endpoints, keys, roles, source maps | access-control, api |
| recon-secrets | .env/.git/keys validation (danger-gated) | supply_chain, cloud_iam_privesc |
| recon-cloud | cloud assets, S3, metadata targets, takeovers | cloud_iam_privesc, ssrf |
| sqli | SQL injection: error/bool/time/union/stacked/OOB | nosqli |
| ssrf | URL-fetch/parser/redirect/IMDS/internal pivot | rce, cloud_iam_privesc |
| ssti | template engines → RCE/file read | rce, xss |
| subdomain_takeover | dangling CNAME/NS/cloud-resource takeover | recon-subdomains |
| supply_chain | secret-driven compromise, deps, packages | cloud_iam_privesc |
| xss | reflected/stored/DOM/mutation/CSP | postmessage, cors |

## Auto-invoke trigger table (signal → load)

| Signal | Load | Don't confuse with |
|---|---|---|
| DB error / SQLSTATE / timing-tracking input | sqli | JSON `$ne` objects → nosqli |
| NoSQL `$`-operators / regex keys / `$where` | nosqli | SQL error strings → sqli |
| `id`/`uuid`/`user_id`/`order`/`doc` in path/body | access-control | unauthenticated API path → api |
| Param `redirect/next/url/dest/return/continue/callback` | open_redirect | server-side fetch of it → ssrf |
| Server fetch of user URL / webhook / PDF / avatar / preview | ssrf | client-side redirect → open_redirect |
| `Bearer eyJ…` / JWT cookie | jwt | OAuth token exchange → oauth |
| GraphQL endpoint / introspection / operationName in JS | graphql | REST versioned API → api |
| `{{7*7}}`→49 / `${…}` echoed | ssti | HTML-echo only → xss |
| Upload form / avatar / attachment / import file | file_upload | upload-from-URL → ssrf |
| Serialized blob: `rO0` `O:` `__VIEWSTATE` pickle base64-object | deserialization | JSON API body → api |
| 2FA/OTP/TOTP/verify/resend/backup-code surface | mfa | password reset → account_takeover |
| Login/signup/reset/magic-link/invite flow | authentication | email-change flow → account_takeover |
| Price/quantity/coupon/balance/transfer in body | business-logic | limited-action race → race_condition |
| Token-redeem / vote / wallet / one-use endpoint | race_condition | plain IDOR → access-control |
| `.js` bundle / sourceMappingURL / JS sink string | recon-js | already-parsed endpoint → access-control |
| `.env` `.git` `.bak` `swagger` `actuator` `phpinfo` | recon-secrets | directory listing only → info_disclosure |
| CNAME→NXDOMAIN / NoSuchBucket / parked host | subdomain_takeover | generic DNS noise → recon-subdomains |
| `169.254.169.254` / metadata / IMDS hints in JS | ssrf | cloud config in JS → recon-cloud |
| addEventListener('message') / postMessage(…,'*') | postmessage | ACAO/Origin header → cors |
| `Access-Control-Allow-Origin` / Origin reflection | cors | token-via-postMessage → postmessage |
| LLM chat/agent/RAG ingestion/tool calling | llm_prompt_injection | plain HTML render → xss |
| New domain / apex given (first contact) | recon | subdomain on existing target → recon-subdomains |
| Uploaded file read by parser/thumbnail/office doc | file_upload | PDF-generator fetch → ssrf |
| OAuth / SSO / SAML / redirect_uri / RelayState | oauth | plain bearer JWT → jwt |
| Mobile app / APK / deeplink material | android | mobile REST API → api |
| Verbose stack trace / debug endpoints / version banner | info_disclosure | secret file → recon-secrets |
| AWS/GCP/Azure keys / IAM-like config in JS or files | cloud_iam_privesc | generic secret → recon-secrets |
| Command-string params / shell-echoing inputs | rce | template engine → ssti |

## Master chain map (confirmed primitive → highest-value pivots)

| Confirmed | Pivot → (skill) | Budget note |
|---|---|---|
| sqli | auth bypass → RCE (sqli→authentication→rce) | ≤3 hops |
| nosqli | auth bypass → `$where` RCE (nosqli→rce) | ≤3 hops |
| access-control IDOR | mass-enum → ATO (→account_takeover) | ≤30 reqs |
| api BFLA | admin functions → RCE/data (→access-control/rce) | ≤3 hops |
| ssrf | IMDS → cloud creds (→cloud_iam_privesc); internal → RCE (→rce) | gate: internal_network_authorized |
| file_upload | webshell RCE; stored XSS (→rce/xss) | ≤3 hops |
| xss | session theft → ATO (→account_takeover) | ≤30 reqs |
| open_redirect | OAuth token theft (→oauth) | ≤3 hops |
| jwt forgery | admin endpoints → IDOR sweep (→access-control) | ≤3 hops |
| graphql | mutation authz → data; aliases brute 2FA (→mfa) | ≤3 hops |
| race_condition | double-spend → balance exfil (→business-logic) | ≤3 hops |
| business-logic | price 0 → payment bypass → refund loops | ≤3 hops |
| mfa bypass | ATO via victim 2FA skip (→account_takeover) | ≤3 hops |
| deserialization | RCE (→rce) | 1 hop, direct |
| ssti | RCE (→rce); file read (→info_disclosure) | 1 hop |
| subdomain_takeover | cookie trust → session hijack (→access-control) | ≤3 hops |
| recon-secrets | key→provider compromise (→cloud_iam_privesc/supply_chain) | validate via provider API |
| cors | credentialed read → token theft (→xss if origin needs XSS) | ≤3 hops |
| postmessage | token theft → ATO (→account_takeover) | ≤3 hops |
| osint/recon-osint | new surface → (→recon) | feeds, not a finding |

**Recursion cap:** ≤3 hops from the origin primitive, ≤30 requests per chain. Each hop
must land a NEW primitive; checkpoint at the cap, surface for human go-ahead.