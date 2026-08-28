# Entry point when this runs as the scheduled Lambda (see terraform/main.tf).
# Not wired up yet — see TODO.md, this is an October item.

from scanner.engine import run_scan
from scanner.report import to_json


def handler(event, context):
    # TODO: region should probably come from Lambda env vars, not hardcoded.
    findings = run_scan()

    # TODO: write findings to DynamoDB, publish SNS alert for
    # CRITICAL/HIGH severity findings.

    return {"findings": to_json(findings)}
