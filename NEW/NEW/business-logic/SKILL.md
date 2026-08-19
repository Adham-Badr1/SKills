---
name: business-logic
description: >-
  Business logic flaws — price/quantity/coupon abuse, payment state-machine gaps,
  client-trusted entitlements, limit bypasses, negative/refund loops, OTP-as-gate
  bypasses, verification-limit skips. Auto-invoke when: price/total/amount/quantity/
  credits/discount in bodies, step/status/flow-state params, use-once endpoints
  (coupon/vote/transfer), payment URLs, JS betraying client-side enforcement. Do NOT
  load for: plain IDOR/authz → `access-control`; race on the same endpoint →
  `race_condition`.
family: state-machine
severity: medium → critical
---

# Business Logic — money · states · limits · entitlement abuse

> **Arsenal:** free purchases, negative balances, unlimited coupons/transfers, skipped
> payment gates, refund loops → direct financial loss.
> **Sibling:** `race_condition` (concurrency), `access-control` (entitlement flags),
> `mfa` (2FA-as-payment-gate), `api` (hidden params that flip states).
> **Proof bar:** observed state change with real value — price honored at 0, balance
> moved/refunded without payment, coupon reusable, quota bypassed. Client-side price
> edit alone without effect is `possible`.
> **Setup:** A + B accounts; money endpoints on BOTH to observe ownership/binding.

## WAF Bypass (business logic)
- Hidden params: `discount`, `coupon`, `amount`, `price`, `quantity`, `currency`, `status`, `step`, `type`, `isFree` in JSON/query — server binds them
- Multipart/duplicate: same field twice — server uses the SECOND (HPP); array values accepted
- Negative values: `quantity=-1`, `amount=-100` → credit loops · float/NaN: `amount=0.0000001`, `NaN`, `Infinity`
- Overflow: `quantity=999999999999` → int overflow to 0/negative
- Currency switch: `currency=EUR` → `currency=BTC` mismatched conversion rounding
- String/type confusion: `amount="0"`, `coupon=[]`, `price=null` — binders coerce

## Context
- Logic bugs live in the WORKFLOW: cart→checkout→payment→fulfillment. Map every step's input
  and validation, then attack transitions: skip a step, rewind a step, duplicate a step, feed
  negative values, or replay the whole flow with mutated state.

## General Techniques
- **Price/quantity in client:** set `price:0`/`total:0`/`quantity:-1` — server honors
- **Coupon abuse:** stacking (multi-coupon), negative coupons, reuse of single-use, self-referral cycles
- **State-machine skip:** jump to `step=confirmed`/`status=paid` without payment; delete/replay order IDs
- **Foreign order reuse:** pay for order A, apply token to order B (same total → different order)
- **Limit bypass:** counters keyed on spoofable keys (IP, device, email variants, cart re-creation)
- **OTP/2FA as gate:** nullable verify params — skip or null the gate (→ `mfa`)
- **Entitlement flags client-trusted:** `isPro:true`/`plan:"enterprise"` in request honored
- **Refund/balance loops:** negative transfers, refund of free items, transfer-to-self profit
- **Voucher/vote/transfer single-use:** server re-checks or trusts client? race the counter (→ `race_condition`)
- **Currency/rounding:** 0.1+0.2 float math — 3-decimal rounds to profit; FX conversion double-round
- **Quantity limits:** buy 1 → change cart qty post-price-calc; split shipments to bypass min-quantity
- **Price read-back:** response includes final price — edit before next step (TOCTOU price check)

## Second-Order & Bypass Techniques
- Cart price locked at step 1, mutated at step 3 — validation gap between steps (snapshot vs live)
- Coupon issued for account A, redeemable cross-account — stolen/linked discounts
- Gift-card balance: top-up negative, redemption race, PIN brute (low entropy)

## Auth Bypass Techniques
- Admin/discount endpoints callable with user token (BFLA on money ops) (→ `access-control`)
- Refund APIs without ownership check → refund OTHERS' orders to your account (IDOR+logic)

## Header Techniques
- `X-Forwarded-For`/device headers keying quotas — rotate to bypass per-user limits
- `Referer`/Origin trust for payment callback validation (no HMAC → fake callbacks)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| CVE-2021-40444-style | (rare dedicated CVEs — logic is per-app) | n/a — treat each app fresh |
| CVE-2019-19781 | Citrix ADC | (authz family used as logic demo) |

## Indicators — record as `possible` when seen
- Price/total/discount/coupon/quantity/credits/currency in ANY request body (esp. JS-derived)
- step/status/phase/state params on checkout · payment callback endpoints (webhook/paypal/COD)
- "use once" endpoints: vote, transfer, coupon, gift-card, referral codes
- Client-side JS computing totals with server-side sync at "pay" only

## Tools
- `curl -s -X POST URL/checkout -d '{"total":0,"coupon":"FREENOW"}'` — mutation observed via order page
- Burp macros to walk the cart→checkout→pay flow with mutated step params
- `ffuf` hidden-param discovery on checkout steps (`-w logic-params.txt -u URL/checkout -X POST -d 'FUZZ=1'`)
- Compare POST bodies between normal and replayed flows (diff the state)