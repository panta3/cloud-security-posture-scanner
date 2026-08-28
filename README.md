# Cloud Security Posture Scanner

Audits an AWS account against CIS AWS Foundations Benchmark controls,
scores findings by severity, and (optionally) auto-remediates a few
low-risk ones. Runs on a schedule via Lambda + EventBridge, not as a
script you remember to run manually.

## Architecture
```
EventBridge (schedule) -> Lambda (scanner) -> DynamoDB (findings)
                                            -> SNS (alerts on Critical/High)
```
- **Rule engine** (`src/scanner/rules/`): each check is its own file
  implementing the `Rule` interface — new checks don't touch core logic.
- **Least-privilege scanner role**: the scanner only ever gets read-only
  IAM permissions on the resources it audits.
- **Cross-account (stretch)**: AssumeRole support so one deployment can
  scan multiple AWS accounts.
- **IaC**: infra defined in `terraform/`, not created by hand in the console.

## CIS checks planned for v1
- [ ] S3 buckets with public access
- [ ] IAM policies with wildcard (`*:*`) actions
- [ ] Security groups open to `0.0.0.0/0` on sensitive ports
- [ ] RDS instances publicly accessible
- [ ] EBS volumes without encryption
- [ ] CloudTrail not enabled in all regions

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

## Status
Scaffolded — rule engine skeleton in place, no rules implemented yet.
See `TODO.md`.
