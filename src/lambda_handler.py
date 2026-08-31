import os

from scanner.engine import run_scan
from scanner.report import to_json
from scanner.notify import write_findings, publish_alerts


def handler(event, context):
    # No region param needed here — Lambda sets AWS_REGION in its own
    # execution environment automatically, and boto3.Session() picks that
    # up on its own when region isn't passed explicitly.
    findings = run_scan()

    # write_findings returns only the findings that are genuinely new this
    # run (not ones that were already ACTIVE last scan) — that's what
    # publish_alerts should page on, not every still-standing issue.
    new_findings = write_findings(findings, table_name=os.environ["FINDINGS_TABLE_NAME"])
    publish_alerts(new_findings, topic_arn=os.environ["ALERTS_TOPIC_ARN"])

    return {"findings": to_json(findings), "new_findings": len(new_findings)}
