import logging
import os
import time

import boto3

from scanner.engine import run_scan
from scanner.report import to_json
from scanner.notify import write_findings, publish_alerts
from scanner.remediation import remediate_findings
from scanner.metrics import publish_scan_metrics

logger = logging.getLogger(__name__)


def handler(event, context):
    # No region param needed here — Lambda sets AWS_REGION in its own
    # execution environment automatically, and boto3.Session() picks that
    # up on its own when region isn't passed explicitly.
    scan_start = time.monotonic()
    findings = run_scan()
    scan_duration = time.monotonic() - scan_start

    table_name = os.environ["FINDINGS_TABLE_NAME"]

    # write_findings returns only the findings that are genuinely new this
    # run (not ones that were already ACTIVE last scan) — that's what
    # publish_alerts should page on, not every still-standing issue.
    new_findings = write_findings(findings, table_name=table_name)

    # Empty by default — auto-remediation is opt-in per rule ID, set via
    # this env var (comma-separated, e.g. "S3.1,RDS.1"), never a blanket
    # "remediate everything" switch. Not set at all means fully read-only.
    enabled_rule_ids = {
        r.strip() for r in os.environ.get("AUTO_REMEDIATE_RULES", "").split(",") if r.strip()
    }
    remediated: list = []
    if enabled_rule_ids:
        remediated = remediate_findings(
            findings, enabled_rule_ids, boto3.Session(), table_name=table_name
        )

    publish_alerts(
        new_findings, topic_arn=os.environ["ALERTS_TOPIC_ARN"], remediated=remediated
    )

    # Best-effort — a metrics publish failure shouldn't fail the whole
    # scan (findings are already durably written by this point), but it
    # should still show up in the logs instead of vanishing silently.
    try:
        publish_scan_metrics(findings, new_findings, remediated, scan_duration)
    except Exception:
        logger.exception("Failed to publish CloudWatch metrics")

    return {
        "findings": to_json(findings),
        "new_findings": len(new_findings),
        "remediated": len(remediated),
        "scan_duration_seconds": scan_duration,
    }
