import logging
from datetime import datetime, timezone

import boto3

from .engine import ALL_RULES
from .rules.base import Finding

logger = logging.getLogger(__name__)

_RULES_BY_ID = {rule.id: rule for rule in ALL_RULES}


def remediate_findings(
    findings: list[Finding],
    enabled_rule_ids: set[str],
    session,
    table_name: str,
) -> list[Finding]:
    """
    Only touches a finding if its rule is BOTH remediable (a deliberate,
    per-rule decision — see rules/base.py) AND its rule_id is explicitly
    in enabled_rule_ids, which the caller controls (env var in Lambda,
    CLI flag locally). Neither alone is enough — a rule being capable of
    remediation doesn't mean this deployment wants it to run
    unsupervised.

    Returns the findings that were actually remediated. Writes an audit
    record (remediated_at / remediated_by) onto each finding's row in
    the findings table — a durable trail of what the scanner changed and
    when, independent of the ACTIVE/RESOLVED status a later scan will
    naturally set once the underlying resource reflects the fix.
    """
    remediated: list[Finding] = []
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)

    for finding in findings:
        rule = _RULES_BY_ID.get(finding.rule_id)
        if rule is None or not rule.remediable or finding.rule_id not in enabled_rule_ids:
            continue

        try:
            rule.remediate(session, finding.resource_id)
        except Exception:
            # One resource we can't fix (permissions, it was deleted
            # mid-scan, etc.) shouldn't stop remediation of everything
            # else that's opted in.
            logger.exception(
                "Remediation failed for %s#%s", finding.rule_id, finding.resource_id
            )
            continue

        remediated.append(finding)
        table.update_item(
            Key={"id": f"{finding.rule_id}#{finding.resource_id}"},
            UpdateExpression="SET remediated_at = :now, remediated_by = :who",
            ExpressionAttributeValues={
                ":now": datetime.now(timezone.utc).isoformat(),
                ":who": "posture-scanner-auto-remediation",
            },
        )

    return remediated
