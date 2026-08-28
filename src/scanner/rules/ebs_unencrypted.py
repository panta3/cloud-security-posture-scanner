from .base import Rule, Finding, Severity


class EBSUnencryptedRule(Rule):
    id = "EC2.2"
    severity = Severity.MEDIUM

    def check(self, session) -> list[Finding]:
        ec2 = session.client("ec2")
        findings: list[Finding] = []

        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page["Volumes"]:
                if not volume.get("Encrypted"):
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            resource_id=volume["VolumeId"],
                            severity=self.severity,
                            message=f"EBS volume '{volume['VolumeId']}' is not encrypted.",
                        )
                    )

        return findings
