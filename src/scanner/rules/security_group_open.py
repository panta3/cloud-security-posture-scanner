from .base import Rule, Finding, Severity

SENSITIVE_PORTS = {22, 3389, 3306, 5432}
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def _rule_covers_sensitive_port(perm: dict) -> bool:
    # AWS uses IpProtocol "-1" as a sentinel meaning "all protocols, all
    # ports" — there's no FromPort/ToPort to check in that case, the rule
    # covers everything by definition.
    if perm.get("IpProtocol") == "-1":
        return True

    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return False

    return any(from_port <= port <= to_port for port in SENSITIVE_PORTS)


def _rule_open_to_internet(perm: dict) -> bool:
    cidrs = {r["CidrIp"] for r in perm.get("IpRanges", [])}
    cidrs |= {r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])}
    return bool(cidrs & OPEN_CIDRS)


class OpenSecurityGroupRule(Rule):
    id = "EC2.1"
    severity = Severity.HIGH

    def check(self, session) -> list[Finding]:
        ec2 = session.client("ec2")
        findings: list[Finding] = []

        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    if _rule_open_to_internet(perm) and _rule_covers_sensitive_port(
                        perm
                    ):
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                resource_id=sg["GroupId"],
                                severity=self.severity,
                                message=(
                                    f"Security group '{sg['GroupId']}' "
                                    f"({sg.get('GroupName', '')}) allows inbound "
                                    "traffic from the internet on a sensitive port."
                                ),
                            )
                        )
                        break  # one finding per security group is enough

        return findings
