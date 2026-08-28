import uuid
from datetime import datetime, timezone

import boto3

from .rules.base import Finding, Severity

ALERTABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def write_findings(findings: list[Finding], table_name: str) -> None:
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    scanned_at = datetime.now(timezone.utc).isoformat()

    # batch_writer handles chunking and retries automatically instead of
    # looping individual put_item calls by hand.
    with table.batch_writer() as batch:
        for finding in findings:
            batch.put_item(
                Item={
                    "id": str(uuid.uuid4()),
                    "scanned_at": scanned_at,
                    "rule_id": finding.rule_id,
                    "resource_id": finding.resource_id,
                    "severity": finding.severity.value,
                    "message": finding.message,
                }
            )


def publish_alerts(findings: list[Finding], topic_arn: str) -> None:
    # Only Critical/High findings page anyone — a Medium/Low finding in
    # every scan's alert would just train everyone to ignore the topic.
    alertable = [f for f in findings if f.severity in ALERTABLE_SEVERITIES]
    if not alertable:
        return

    lines = [
        f"[{f.severity}] {f.rule_id} — {f.resource_id}: {f.message}"
        for f in alertable
    ]

    sns = boto3.client("sns")
    sns.publish(
        TopicArn=topic_arn,
        Subject=f"Posture Scanner: {len(alertable)} Critical/High finding(s)",
        Message="\n".join(lines),
    )
