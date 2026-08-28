from scanner.rules.base import Finding


def print_report(findings: list[Finding]) -> None:
    # TODO: group by severity, add counts summary at the top.
    if not findings:
        print("No findings.")
        return

    for f in findings:
        print(f"[{f.severity}] {f.rule_id} — {f.resource_id}: {f.message}")


def to_json(findings: list[Finding]) -> list[dict]:
    # TODO: this is what gets written to DynamoDB once the pipeline exists.
    return [
        {
            "rule_id": f.rule_id,
            "resource_id": f.resource_id,
            "severity": f.severity,
            "message": f.message,
        }
        for f in findings
    ]
