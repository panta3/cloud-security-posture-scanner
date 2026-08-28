# TODO — Cloud Security Posture Scanner

## September
- [x] Implement `Rule` base + engine runner (`src/scanner/engine.py`)
- [x] Implement first 5 CIS checks (see README) in `src/scanner/rules/`
- [x] CLI entry point that runs all rules against a given AWS profile, prints a report
- [x] Set up a sandbox AWS account/IAM user to actually test against
- [x] Validated detection end-to-end: deliberately created a public S3 bucket, confirmed the scanner flagged it (S3.1, CRITICAL), cleaned up, confirmed the scan goes clean again

## October
- [x] `src/lambda_handler.py` — wrap the engine for Lambda invocation
- [x] Wire report output to DynamoDB + SNS alert on Critical/High findings (`src/scanner/notify.py`)
- [x] `terraform/`: Lambda function, EventBridge schedule rule, DynamoDB table for findings, SNS topic, least-privilege IAM role for the scanner itself
- [x] Deploy via `terraform apply` (8 resources), confirmed a manual invoke fires correctly and writes to DynamoDB (EventBridge's `rate(1 day)` schedule itself not yet observed firing on its own — would take 24h to see)

## November
- [ ] Opt-in auto-remediation for 1-2 low-risk findings (e.g. block public S3 access) — behind an explicit flag, never automatic by default
- [ ] CloudWatch dashboard: scan latency, findings count over time
- [ ] README screenshots/demo of a real findings report
- [ ] Stretch: K8s CIS Benchmark checks against a local kind/minikube cluster
- [ ] Findings never get marked resolved — every scan just appends new rows, so a fixed issue's old finding sits in DynamoDB forever. Worth deciding: TTL on items, or a resolved/active status column.

## Notes
- Keep rules read-only by default. Auto-remediation is opt-in and scoped tight.
- Test each rule against a deliberately misconfigured sandbox resource before trusting it
  (done for S3.1, including the full Lambda → DynamoDB write path — IAM.1, EC2.1, RDS.1, EC2.2 still only validated on the negative case).
- Live in the sandbox account as of 2026-08-28: Lambda `posture-scanner`, DynamoDB `posture-scanner-findings`, SNS `posture-scanner-alerts`, EventBridge rule `posture-scanner-schedule`. Run `terraform destroy` in `terraform/` to tear down.
