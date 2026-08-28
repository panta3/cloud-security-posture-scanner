# TODO — Cloud Security Posture Scanner

## September
- [ ] Implement `Rule` base + engine runner (`src/scanner/engine.py`)
- [ ] Implement first 5-8 CIS checks (see README) in `src/scanner/rules/`
- [ ] CLI entry point that runs all rules against a given AWS profile, prints a report
- [ ] Set up a sandbox AWS account/IAM user to actually test against — don't run this against anything that matters yet

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
- Test each rule against a deliberately misconfigured sandbox resource before trusting it.
