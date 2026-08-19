---
name: recon-cloud
description: >-
  Cloud asset recon — S3 buckets, cloud CNAMEs (S3/CloudFront/ELB/ASW/GC), metadata
  targets, container registries, open buckets, storage policies, takeover candidates.
  Auto-invoke when: recon tier 5-6 runs, CNAMEs to cloud services, S3/gs://bucket names
  seen, metadata endpoint hints, cloud tech fingerprint (x-amz-*, google-storage).
  Do NOT load for: claiming takeovers → `subdomain_takeover`; using cloud keys →
  `cloud_iam_privesc`/`recon-secrets`.
family: sink-signal
severity: info → high (open buckets)
---

# Recon-Cloud — buckets · CNAMEs · registries · metadata

> **Arsenal:** open storage buckets (read/list/write), cloud-hosted assets, metadata-
> endpoint targets, cloud takeover candidates.
> **Sibling:** `subdomain_takeover` (claiming), `cloud_iam_privesc` (keys),
> `ssrf` (IMDS use), `recon-secrets` (cloud keys).
> **Proof bar:** bucket list/read/write demonstrated (an object read you shouldn't see,
> or list permission on others' data) — verified against the STORAGE API, not a 200.
> **Setup:** in-scope asset confirmed (bucket belongs to target per DNS/CNAME/documentation).

## WAF Bypass (cloud recon — the gates are bucket policies)
- Header fingerprint: `x-amz-*` (S3), `google-storage` (GCS), `x-ms-*` (Azure Blob) → provider identified
- Region rotation: `bucket.s3.amazonaws.com` vs `bucket.s3.<region>.amazonaws.com` — cross-region policy differences
- Path-style vs virtual-host: `s3.<region>.amazonaws.com/<bucket>/` vs `<bucket>.s3...` — access modes differ
- Prefix/version access: `?prefix=`, `?versions`, `?list-type=2` — enumeration variants
- Signed-URL hints: presigned URLs in JS (→ key material/validity window)

## Context
- Cloud assets leak via: DNS CNAMEs (S3/CloudFront/ELB/Heroku/GC), JS bundle URLs (storage
  endpoints), docs, certificate SANs, and open-bucket guessing. They matter because storage
  policies default-open in some configs, and they route SSRF/metadata chains.

## General Techniques
- **Bucket guessing:** `<target>-assets`, `<target>-backup`, `<target>-data`, `<target>-uploads`, `dev-`, `test-`, `staging-` combos
- **List check:** `curl -s https://<bucket>.s3.amazonaws.com/?list-type=2` → object inventory
- **Read check:** fetch a known object path (from JS/wayback) without auth
- **Write check (authorized only):** PUT a benign probe object (marker, then delete)
- **Policy check:** `curl -sI <bucket>/` → `403 AccessDenied` vs 200 — open vs closed
- **CNAME map:** dnsx CNAME output → cloud-service targets (→ subdomain_takeover candidates)
- **Registry scan:** docker/container registries in cloud (ECR/ACR/GCR) — public repo listing
- **Metadata targets inventory:** note 169.254.169.254 / metadata.google.internal routes for LATER SSRF (→ ssrf)
- **Storage URLs in JS:** `storage.googleapis.com`, `s3.amazonaws.com`, Azure blob URLs in bundles (→ recon-js)
- **CDN/edge configs:** CloudFront distributions → origin reveal (→ recon-infra origin hunt)
- **Firebase/Supabase:** `firebaseio.com`/`supabase.co` in JS → rules check (→ cloud_iam_privesc)
- **Presigned URL abuse:** leaked signed URLs → object read until expiry (→ recon-secrets)

## Second-Order & Bypass Techniques
- Bucket in a DIFFERENT account than the target (shared-services bucket) — the policy matters more than the owner
- Versioning: `?versions` shows DELETED objects (data resurrection)

## Auth Bypass Techniques
- Bucket ACLs with `AllUsers`/`AuthenticatedUsers` grants → list/read/write without creds
- CloudFront signed-URL guessing (rare) — record only

## Header Techniques
- `Server: AmazonS3`/`GoogleFrontend`/`x-ms-blob-type` → provider + storage surface
- `x-amz-request-id` in error bodies → confirms bucket name validity (enumeration oracle)

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (bucket misconfigs = config, not CVE; provider-version CVEs → owning skills) | — | — |

## Indicators — record as `possible` when seen
- CNAMEs → cloud services · `x-amz-*`/`google-storage`/`x-ms-*` headers · bucket URLs in JS
- 403 AccessDenied on list (bucket EXISTS → target), 200 on list (open bucket)
- Metadata endpoint reachable from SSRF-capable params (→ ssrf) · storage URLs in app bundles

## Tools
- `curl -s 'https://<bucket>.s3.amazonaws.com/?list-type=2' | head` (list probe)
- `cloud_enum`/`s3scanner`/`lazys3` for bucket triage (authorized targets only)
- `dnsx -cname` map → cloud CNAMEs; `dig +short <sub> CNAME`
- `curl -sI 'https://<bucket>.s3.amazonaws.com/' | grep -iE 'x-amz|server'` (fingerprint)