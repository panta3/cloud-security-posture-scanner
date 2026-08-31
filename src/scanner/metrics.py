import boto3

from .rules.base import Finding, Severity

NAMESPACE = "PostureScanner"


def publish_scan_metrics(
    findings: list[Finding],
    new_findings: list[Finding],
    remediated: list[Finding],
    scan_duration_seconds: float,
) -> None:
    """
    Everything the CloudWatch dashboard renders comes from here — Lambda's
    own built-in metrics (Duration, Errors, Invocations) already exist for
    free, but "how many findings exist right now, broken down by
    severity" is domain-specific and nobody publishes that but us.
    """
    cloudwatch = boto3.client("cloudwatch")

    by_severity = {s: 0 for s in Severity}
    for f in findings:
        by_severity[f.severity] += 1

    metric_data = [
        {
            "MetricName": "ScanDuration",
            "Value": scan_duration_seconds,
            "Unit": "Seconds",
        },
        {
            "MetricName": "TotalFindings",
            "Value": len(findings),
            "Unit": "Count",
        },
        {
            "MetricName": "NewFindings",
            "Value": len(new_findings),
            "Unit": "Count",
        },
        {
            "MetricName": "RemediatedFindings",
            "Value": len(remediated),
            "Unit": "Count",
        },
    ]

    for severity, count in by_severity.items():
        metric_data.append(
            {
                "MetricName": "FindingsBySeverity",
                "Dimensions": [{"Name": "Severity", "Value": severity.value}],
                "Value": count,
                "Unit": "Count",
            }
        )

    # put_metric_data caps at 20 data points per call — 8 here, well
    # under it, so no batching needed. Worth revisiting if more
    # dimensions get added later.
    cloudwatch.put_metric_data(Namespace=NAMESPACE, MetricData=metric_data)
