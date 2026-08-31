import time
from datetime import datetime, timezone

import boto3
from boto3.dynamodb.conditions import Attr

from .rules.base import Finding, Severity

ALERTABLE_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}
RESOLVED_TTL_DAYS = 30


def _finding_key(finding: Finding) -> str:
    # Deterministic, not a random UUID — the same misconfiguration found
    # again on the next scan updates this one row instead of piling up a
    # fresh duplicate every run.
    return f"{finding.rule_id}#{finding.resource_id}"


def write_findings(findings: list[Finding], table_name: str) -> list[Finding]:
    """Upserts current findings as ACTIVE, marks anything that dropped out
    of this scan as RESOLVED, and returns only the genuinely new findings
    (for alerting — see publish_alerts)."""
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    now = datetime.now(timezone.utc).isoformat()

    # A full table scan doesn't hold up at real scale, but this table is
    # bounded by "misconfigurations across one account" — a GSI on status
    # would be the fix if that ever stops being true.
    previously_active = table.scan(FilterExpression=Attr("status").eq("ACTIVE"))
    previously_active_keys = {item["id"] for item in previously_active["Items"]}
    current_keys = {_finding_key(f) for f in findings}

    new_findings = [f for f in findings if _finding_key(f) not in previously_active_keys]

    for finding in findings:
        table.update_item(
            Key={"id": _finding_key(finding)},
            UpdateExpression=(
                "SET rule_id = :rule_id, resource_id = :resource_id, "
                "severity = :severity, message = :message, "
                "#status = :active, last_seen = :now, "
                "first_seen = if_not_exists(first_seen, :now) "
                "REMOVE expires_at"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":rule_id": finding.rule_id,
                ":resource_id": finding.resource_id,
                ":severity": finding.severity.value,
                ":message": finding.message,
                ":active": "ACTIVE",
                ":now": now,
            },
        )

    # Anything ACTIVE before this scan that isn't ACTIVE anymore was
    # fixed. Mark it RESOLVED with a TTL so it doesn't sit in the table
    # forever, but keep it around briefly rather than deleting it outright
    # — there's value in a short audit trail of what got fixed and when.
    resolved_keys = previously_active_keys - current_keys
    expires_at = int(time.time()) + RESOLVED_TTL_DAYS * 86400

    for key in resolved_keys:
        table.update_item(
            Key={"id": key},
            UpdateExpression="SET #status = :resolved, resolved_at = :now, expires_at = :expiry",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":resolved": "RESOLVED",
                ":now": now,
                ":expiry": expires_at,
            },
        )

    return new_findings


def publish_alerts(findings: list[Finding], topic_arn: str) -> None:
    # Only Critical/High findings page anyone — a Medium/Low finding in
    # every scan's alert would just train everyone to ignore the topic.
    # Callers should pass only *new* findings here (see write_findings) —
    # re-alerting on something that's been sitting ACTIVE for a week
    # trains people to ignore the topic just as fast as noisy severities do.
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
        Subject=f"Posture Scanner: {len(alertable)} new Critical/High finding(s)",
        Message="\n".join(lines),
    )
