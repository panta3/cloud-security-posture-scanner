from .base import Rule, Finding, Severity


class RDSPubliclyAccessibleRule(Rule):
    id = "RDS.1"
    severity = Severity.CRITICAL
    remediable = True

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

    def remediate(self, session, resource_id: str) -> None:
        # Flips PubliclyAccessible off — a network-reachability setting,
        # not a data-affecting change. ApplyImmediately=True so the fix
        # takes effect right away instead of waiting for the instance's
        # next maintenance window, which would leave it exposed longer
        # than necessary for something this cheap to fix.
        rds = session.client("rds")
        rds.modify_db_instance(
            DBInstanceIdentifier=resource_id,
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )
