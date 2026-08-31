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
- [x] Findings lifecycle: deterministic key (`rule_id#resource_id`) instead of random UUID, so re-scanning upserts instead of duplicating. Status field (ACTIVE/RESOLVED), `first_seen`/`last_seen`/`resolved_at` timestamps. RESOLVED findings get a 30-day TTL (`expires_at`) so they clean up automatically instead of accumulating forever. Alerts now only fire for genuinely *new* findings, not every still-standing one (was re-alerting daily on the same issue before).
- [ ] Opt-in auto-remediation for 1-2 low-risk findings (e.g. block public S3 access) — behind an explicit flag, never automatic by default
- [ ] CloudWatch dashboard: scan latency, findings count over time
- [ ] README screenshots/demo of a real findings report
- [ ] Stretch: K8s CIS Benchmark checks against a local kind/minikube cluster

## Notes
- Keep rules read-only by default. Auto-remediation is opt-in and scoped tight.
- Test each rule against a deliberately misconfigured sandbox resource before trusting it
  (done for S3.1, including the full Lambda → DynamoDB write path — IAM.1, EC2.1, RDS.1, EC2.2 still only validated on the negative case).
- Live in the sandbox account as of 2026-08-28: Lambda `posture-scanner`, DynamoDB `posture-scanner-findings`, SNS `posture-scanner-alerts`, EventBridge rule `posture-scanner-schedule`. Run `terraform destroy` in `terraform/` to tear down.
- IAM policy needs to grant exactly what the code calls — the switch to Scan+UpdateItem broke against the old PutItem/BatchWriteItem-only policy until caught and fixed. Worth re-checking any time notify.py's DynamoDB calls change.
- Default 128MB Lambda memory hit its ceiling on one run and the invocation timed out with no error logged (likely GC/network thrashing) — bumped to 256MB (Lambda scales CPU with memory) and it's been stable since.
