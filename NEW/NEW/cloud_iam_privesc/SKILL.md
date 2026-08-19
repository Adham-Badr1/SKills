---
name: cloud_iam_privesc
description: >-
  Cloud IAM privilege escalation — AWS/GCP/Azure misconfigurations: overbroad policies,
  PassRole, wildcard trust, permission-boundary escapes, IMDS/SSRF credential theft,
  lambda inner-role hijack, S3/KMS resource-policy abuse, MFA/SAML manipulation.
  Auto-invoke when: AWS/GCP/Azure keys/config in JS/files/env, IAM role names visible,
  S3 buckets, IMDS reachable, cloud-specific headers/regions, terraform/cloudformation
  dumps. Do NOT load for: generic secrets → `recon-secrets`; SSRF-only reach →
  `ssrf`.
family: state-machine
severity: critical
---

# Cloud IAM Privesc — AWS · GCP · Azure role escalation

> **Arsenal:** escalate from a low-privilege cloud identity to admin/root, exfil data
> from S3/databases, mint tokens.
> **Sibling:** `ssrf` (IMDS route in), `recon-secrets` (key discovery), `supply_chain`
> (repo secrets), `recon-cloud` (asset inventory).
> **Proof bar:** observed privilege gain — a permission you didn't have now works
> (verified against the provider API), or data from a protected resource read, or a
> token minted for a role you couldn't assume. Config-suspect alone = `possible`.
> **Setup:** the identity/keys in hand (from recon-secrets/IMDS/repo); cloud CLI installed
> (`aws`/`gcloud`/`az`); NEVER log real keys — validate, record provider+last4+valid.

## WAF Bypass (cloud — no WAF; the gates are IAM policies and STS)
- IMDSv2: PUT token with TTL required — GET token first, then metadata (→ `ssrf`)
- Permission-boundary escape: role with boundary still calls `iam:CreatePolicyVersion`-style actions
- Policy version rollback: overwrite the ACTIVE policy version with an old permissive one
- Resource-policy self-grant: modify your OWN role's trust policy (iam:UpdateAssumeRolePolicy)
- Token confusion: minted token reused across accounts (confused-deputy)

## Context
- Privesc = one of: (1) you hold a role that can mutate policies, (2) you can PassRole to
  compute you control, (3) trust policies are overbroad, (4) resource policies (S3/KMS) grant you
  more, (5) SSRF gives you IMDS. Map your CURRENT effective permissions first
  (`aws sts get-caller-identity` + policy enumeration) — never guess.

## General Techniques
- **iam:AttachUserPolicy/AttachRolePolicy:** attach `AdministratorAccess` to your user/role
- **iam:PutUserPolicy / PutRolePolicy:** inline policy self-grant
- **iam:CreatePolicyVersion + SetDefaultPolicyVersion:** roll back/override an existing policy
- **sts:AssumeRole with wildcard/weak trust:** role trusts `*` / any-account → assume it
- **PassRole to EC2/Lambda/ECS/Glue/CloudFormation:** launch compute with the privileged role, pull creds from its metadata/env
- **lambda:UpdateFunctionCode:** redeploy a function attached to a strong execution role → code reads its env creds
- **Lambda inner-role hijack:** function's execution role writeable → swap code for credential-printing handler
- **iam:UpdateAssumeRolePolicy:** add YOUR account to the target role's trust → assume
- **iam:UpdateLoginProfile / iam:CreateAccessKey:** mint credentials on a privileged USER
- **iam:DeactivateMFADevice / DeleteVirtualMFADevice:** strip MFA from a protected user
- **iam:UpdateSAMLProvider / CreateSAMLProvider:** register attacker IdP → admin via SSO
- **KMS key-policy self-grant:** key policy allows `kms:*` to you / `kms:Decrypt` on protected keys
- **S3 bucket-policy/ACL:** bucket grants `s3:*` to authenticated users → read/write data
- **EC2 user-data / snapshot:** read user-data scripts (creds), mount EBS snapshots with secrets
- **GCP:** custom-role create/update with `iam.roles.create`, service-account `iam.serviceAccounts.signBlob/signJwt` token forging, implicit delegation chains
- **GCP SA token minting:** `serviceusage`-granted SA with token creator → mint scoped tokens
- **Azure:** RBAC role assignment self-grant, managed-identity token theft via metadata endpoint
- **Confused deputy / cross-account:** attacker role ARN used in another account's policies

## Second-Order & Bypass Techniques
- Chains: SSRF→IMDS (role A) → PassRole to role B → role B has KMS decrypt → decrypt vault
- Tag-based conditions: `aws:ResourceTag` grants — create a resource with the required tag to pass the condition

## Auth Bypass Techniques
- IAM users with console password + `iam:ChangePassword` → change admin? no — change YOUR own, then escalate via other paths
- STS token without MFA where policy `aws:MultiFactorAuthPresent` missing → forged MFA-less sessions

## Header Techniques
- Metadata: `X-aws-ec2-metadata-token` (IMDSv2 PUT) — full token flow; `Metadata-Flavor: Google` (GCE)
- Azure: `Metadata: true` header on 169.254.169.254/metadata/instance

## CVE on Sight
| CVE | Surface | Class |
|---|---|---|
| (IAM misconfigs are configuration CVEs) | — | treat per policy |
| CVE-2021-35608 / 35607 (AWS MSK) | MSK | IAM auth bypass (family) |
| CVE-2022-23806 (various cloud libs) | SDK trust | token confusion (family) |

## Indicators — record as `possible` when seen
- Access keys/roles visible in JS, .env, git history, serverless configs, error pages
- SSRF reaching IMDS/metadata endpoints · S3 buckets enumerable/listable · cloudformation outputs
- IAM role names in error messages; terraform/.aws/config files leaked
- Metadata endpoint reachable: `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`

## Tools
- `aws sts get-caller-identity && aws iam get-account-authorization-details` (YOUR test identity only)
- `pacu` (AWS exploitation framework) — verify chains on YOUR owned test accounts
- `gcloud iam roles list` / `az role assignment list` for GCP/Azure equivalents (test tenants)
- `steampipe`/`cloudfox` for permission-map enumeration; `awscli` sts calls for validation