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
- [x] Opt-in auto-remediation for 2 low-risk findings: S3 public access (blocks it via public access block settings) and RDS public accessibility (flips `PubliclyAccessible` off). Each rule opts into remediation individually (`remediable = True` + a `remediate()` override); the scanner only acts on rule IDs explicitly listed in `AUTO_REMEDIATE_RULES` (Lambda env var, empty by default = fully read-only). Every remediation writes an audit record (`remediated_at`/`remediated_by`) onto the finding's row, and SNS alerts tag auto-fixed findings as `[AUTO-FIXED]` instead of just the severity. Deployed and validated live: created a public S3 bucket, ran remediation, confirmed the block was applied, confirmed the finding transitioned to RESOLVED on the next scan with the audit trail intact.
- [x] CloudWatch dashboard: scan latency, findings count over time. `src/scanner/metrics.py` publishes `ScanDuration`, `TotalFindings`, `NewFindings`, `RemediatedFindings`, and `FindingsBySeverity` (dimensioned by severity) to a custom `PostureScanner` namespace on every invoke, wrapped in its own try/except so a metrics failure can never fail a scan that already wrote findings durably. Dashboard defined in Terraform (`aws_cloudwatch_dashboard.scanner`, 4 widgets: scan duration, findings total/new/remediated, findings by severity, plus Lambda's free built-in Invocations/Errors) so it's provisioned the same way as everything else, not clicked together by hand. Deployed and validated live: invoked the Lambda directly, confirmed no exception in the logs, and confirmed the real data point landed via `get-metric-statistics` (returned the exact `scan_duration_seconds` value the invoke itself reported back). `terraform output dashboard_url` prints the console link.
- [ ] README screenshots/demo of a real findings report
- [ ] Stretch: K8s CIS Benchmark checks against a local kind/minikube cluster

## Notes
- Keep rules read-only by default. Auto-remediation is opt-in and scoped tight.
- Test each rule against a deliberately misconfigured sandbox resource before trusting it
  (done for S3.1, including the full Lambda → DynamoDB write path — IAM.1, EC2.1, RDS.1, EC2.2 still only validated on the negative case; RDS remediation is implemented per the AWS API docs but not yet live-tested against a real RDS instance — spinning one up just for this takes real time/cost, so it's a known gap rather than a silent one).
- Live in the sandbox account as of 2026-08-28: Lambda `posture-scanner`, DynamoDB `posture-scanner-findings`, SNS `posture-scanner-alerts`, EventBridge rule `posture-scanner-schedule`. Run `terraform destroy` in `terraform/` to tear down.
- IAM policy needs to grant exactly what the code calls — the switch to Scan+UpdateItem broke against the old PutItem/BatchWriteItem-only policy until caught and fixed. Worth re-checking any time notify.py's DynamoDB calls change.
- Default 128MB Lambda memory hit its ceiling on one run and the invocation timed out with no error logged (likely GC/network thrashing) — bumped to 256MB (Lambda scales CPU with memory) and it's been stable since.
- **CloudWatch `list-metrics` lags behind reality**: right after the first invoke, `aws cloudwatch list-metrics --namespace PostureScanner` came back empty even though the publish call hadn't errored — `list-metrics` is eventually-consistent and can take a few minutes to index a brand-new namespace/metric. `get-metric-statistics` queried directly against the known metric name showed the real data point immediately. Worth remembering next time a "did the metric actually publish?" check comes back empty right after a first invoke — check `get-metric-statistics` before assuming the publish failed.
- **Real detection bug found while testing remediation**: `get_bucket_policy_status` (used for S3.1 detection) evaluates whether the *policy document* grants public access — it does not factor in whether Block Public Access is currently neutralizing that grant's real-world effect, despite what I originally assumed and documented in the code comment. Consequence: a bucket remediated by enabling Block Public Access (without removing the underlying policy) kept showing up as a finding forever, since the policy document itself never changed — the exact case a working remediation feature needs to handle. Fixed by checking `get_public_access_block` first: if all four block settings are enabled, the bucket is treated as not public regardless of what the policy document says. Verified no regression on the genuinely-public case (block disabled + public policy still gets flagged) with a second live test bucket.
