# Cloud Security Posture Scanner

Audits an AWS account against CIS AWS Foundations Benchmark controls,
scores findings by severity, tracks each finding's lifecycle
(active/resolved, not just a growing pile of rows), and optionally
auto-remediates a couple of low-risk ones. Runs on a schedule via
Lambda + EventBridge, not as a script you remember to run manually.

## Architecture
```
EventBridge (schedule) -> Lambda (scanner) -> DynamoDB (findings, active/resolved)
                                            -> SNS (alerts on new Critical/High)
                                            -> (opt-in) remediation of 2 finding types
```
- **Rule engine** (`src/scanner/rules/`): each check is its own file
  implementing the `Rule` interface — new checks don't touch core logic.
- **Findings lifecycle**: deterministic key (`rule_id#resource_id`), so
  re-scanning upserts instead of duplicating. Findings track ACTIVE vs
  RESOLVED status, and RESOLVED ones auto-expire via DynamoDB TTL after
  30 days instead of accumulating forever.
- **Opt-in remediation**: a rule must explicitly implement `remediate()`
  (only 2 do — S3 public access, RDS public accessibility; both are
  simple, reversible setting toggles, nothing destructive), and the
  scanner only acts on rule IDs an operator explicitly lists via
  `AUTO_REMEDIATE_RULES` — empty by default, fully read-only.
- **Least-privilege scanner role**: read-only permissions for detection,
  plus a narrow, separate IAM statement for the 2 remediation actions —
  kept as its own statement so the "can actually change something"
  surface is obvious at a glance, not buried inside a broader policy.
- **IaC**: infra defined in `terraform/`, not created by hand in the console.

## CIS checks (5/5 implemented, validated against a live sandbox account)
- [x] S3 buckets with public access — **remediable**
- [x] IAM policies with wildcard (`*:*`) actions
- [x] Security groups open to `0.0.0.0/0` on sensitive ports
- [x] RDS instances publicly accessible — **remediable**
- [x] EBS volumes without encryption

## Stretch goal (only if on schedule — see project TODO)
Extend the rule engine to also audit a local Kubernetes cluster (RBAC,
network policies, pod security) against the CIS Kubernetes Benchmark.

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .   # src layout — makes `scanner` importable
python -m scanner.cli --profile <aws-profile>   # local run against your own account
```

To deploy the scheduled Lambda pipeline: `cd terraform && terraform apply`.
To enable remediation, set `auto_remediate_rules = "S3.1,RDS.1"` (or a
subset) as a Terraform variable — left empty by default.

## Status
Core scope complete: detection, the serverless pipeline, findings
lifecycle, and opt-in remediation are all deployed and validated live.
See `TODO.md` for what's left (CloudWatch dashboard, demo screenshots,
optional K8s stretch) and for a couple of real bugs found and fixed
along the way — worth reading if you want the honest version, not just
the checklist.
