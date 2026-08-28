# TODO — Cloud Security Posture Scanner

## September
- [x] Implement `Rule` base + engine runner (`src/scanner/engine.py`)
- [x] Implement first 5 CIS checks (see README) in `src/scanner/rules/`
- [x] CLI entry point that runs all rules against a given AWS profile, prints a report
- [x] Set up a sandbox AWS account/IAM user to actually test against
- [x] Validated detection end-to-end: deliberately created a public S3 bucket, confirmed the scanner flagged it (S3.1, CRITICAL), cleaned up, confirmed the scan goes clean again

## October
- [ ] `lambda_handler.py` — wrap the engine for Lambda invocation
- [ ] `terraform/`: Lambda function, EventBridge schedule rule, DynamoDB table for findings, SNS topic, least-privilege IAM role for the scanner itself
- [ ] Wire report output to DynamoDB + SNS alert on Critical/High findings
- [ ] Deploy via `terraform apply`, confirm a scheduled run actually fires

## November
- [ ] Opt-in auto-remediation for 1-2 low-risk findings (e.g. block public S3 access) — behind an explicit flag, never automatic by default
- [ ] CloudWatch dashboard: scan latency, findings count over time
- [ ] README screenshots/demo of a real findings report
- [ ] Stretch: K8s CIS Benchmark checks against a local kind/minikube cluster

## Notes
- Keep rules read-only by default. Auto-remediation is opt-in and scoped tight.
- Test each rule against a deliberately misconfigured sandbox resource before trusting it
  (done for S3.1 — IAM.1, EC2.1, RDS.1, EC2.2 still only validated on the negative case).
