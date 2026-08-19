---
name: race_condition
description: >-
  Race conditions — TOCTOU double-spend, duplicate payments, token-redeem races,
  2FA enforcement races, rate-limit/anti-bruteforce races, HTTP/2 single-packet
  bursts, session-lock bypass, check-then-act gaps. Auto-invoke when: one-use tokens/
  vouchers/codes, wallet transfers/withdrawals, no idempotency keys on state changes,
  concurrent-write resources, 2FA/code endpoints, vote/limited actions. Do NOT load
  for: sequential logic abuse → `business-logic`; plain IDOR → `access-control`.
family: state-machine
severity: medium → critical
---

# Race Condition — single-packet · TOCTOU · check-then-act

> **Arsenal:** double-spend wallets, duplicate coupons/transfers, skip rate limits,
> mint extra resources — everything a check-then-act gap allows.
> **Sibling:** `business-logic` (sequential abuse), `mfa` (2FA-check races),
> `access-control` (authz-check races), `api` (batching delivery).
> **Proof bar:** two concurrent requests produced TWO state changes where ONE was
> allowed (balance grew, code accepted twice, coupon redeemed twice) — verified by
> read-back. A 200 with no state delta is `possible`.
> **Setup:** A + B accounts; a value-bearing endpoint; delivery via parallel requests.

## WAF Bypass (race)
- Rate-limit bypass IS the race: parallel login/OTP attempts outrun the counter (→ `mfa`)
- HTTP/2 single-packet: N requests in ONE TCP packet — server sees them "simultaneously" (single-packet attack)
- HTTP/2 + GET-parameter mutation: same request, different `x=` — keep server hashes distinct
- Connection reuse: keep-alive same socket, send bursts; some WAFs only filter first request
- Cache-busting params to avoid dedup layers; duplicate headers to split worker queues

## Context
- Race needs a CHECK-then-ACT window: read state (balance/usage), decide, write. When two requests
  pass the check before either writes — double effect. Find them in: single-use codes, balance ops,
  coupon redeem, token issuance, signup bonuses, lockouts, 2FA verification, cart-to-order moves.
- The check may be DB-level (SELECT then UPDATE without conditional) or app-level (in-memory flag).

## General Techniques
- **Wallet withdraw/transfer overdraw:** fire N concurrent withdraws → lost-update double spend
- **Duplicate payment/payout:** pay → pay → two credits; retest with idempotency-key absent
- **Coupon/voucher single-use:** redeem N times concurrently; also confirm post-use state via read-back
- **Token minting:** concurrent token requests (reset/API tokens) → multiple valid tokens
- **2FA enforcement race:** session created before MFA flag set — parallel requests beat the flag write
- **Time-sensitive token:** identical tokens from timestamped PRNG — two requests within same ms
- **Email change + confirm race:** change email while confirming — verify NEW email wins the race
- **OAuth code/refresh race:** code exchange + refresh → both accepted (double-issued session)
- **Rate-limit bypass:** parallel login attempts (anti-bruteforce counter is check-then-act)
- **Checkout snapshot:** cart mutation vs order placement — order priced against mutated cart (→ `business-logic`)
- **DB check-then-act:** missing conditional UPDATE (`WHERE balance >= x`) → negative balance path
- **Multi-endpoint race:** trigger request + N exploitation requests in one burst
- **Session-lock bypass:** one session per request allowed — multi-session bursts beat single-session locks
- **Filesystem TOCTOU:** symlink swap between check and use (→ `file_upload` for upload TOCTOU)
- **Machine-substate discovery:** two-request differential reveals hidden substates (pending/queued)

## Second-Order & Bypass Techniques
- Race the REVERSAL: refund concurrently with charge → both apply; cancel+renew both succeed
- Race the RESET: change email + password in parallel — verify path with old email still valid
- Queue-consumer double-processing: same message delivered twice (no dedup) → double effect

## Auth Bypass Techniques
- 2FA/OTP brute via parallel verification — window widens; counter reset races (→ `mfa`)
- Login lockout bypass: parallel attempts with correct+wrong mixes; counter increments after write

## Header Techniques
- Same cookie across parallel connections (multi-account bursts per connection for split sessions)
- HTTP/2 multiplexing to land requests in one packet; HTTP/1.1 keep-alive pipelining

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (no stable CVEs — race is per-app) | n/a | treat per target |
| CVE-2021-20289 | RDO/Metal3 (edge) | TOCTOU family demo |

## Indicators — record as `possible` when seen
- One-use semantics without server-side lock: coupon, gift card, OTP, reset, transfer, vote, invite
- No `Idempotency-Key`/`X-Request-Id` handling on state-changing endpoints; 201s without dedup
- Balance/quantity counters visible in responses (spendable resources)
- Check-then-act smell: response ordering (approve-then-commit) endpoints, async queue processing

## Tools
- Burp: Turbo Intruder `turbo_intruder` (single-packet) — send N concurrent identical requests
- HTTP/2: `h2c`/ALPN via curl `--http2` for single-packet bursts (`h2_burst.py`-style tooling)
- `curl --parallel --parallel-max 50` URL... — bash-level concurrency (no python)
- Read-back verifier: `curl -s URL/balance` after burst — compare with pre-burst snapshot