from .base import Rule, Finding, Severity


class RDSPubliclyAccessibleRule(Rule):
    id = "RDS.1"
    severity = Severity.CRITICAL

    def check(self, session) -> list[Finding]:
        rds = session.client("rds")
        findings: list[Finding] = []

        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for instance in page["DBInstances"]:
                if instance.get("PubliclyAccessible"):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            resource_id=instance["DBInstanceIdentifier"],
                            severity=self.severity,
                            message=(
                                f"RDS instance '{instance['DBInstanceIdentifier']}' "
                                "is publicly accessible."
                            ),
                        )
                    )

        return findings
