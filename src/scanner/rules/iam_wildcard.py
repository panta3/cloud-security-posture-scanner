from botocore.exceptions import ClientError

from .base import Rule, Finding, Severity


def _as_list(value):
    # IAM policy JSON allows Action/Resource to be either a single string
    # or a list of strings — normalize to a list once so the rest of the
    # check doesn't need to handle both shapes everywhere it looks at them.
    return value if isinstance(value, list) else [value]


class IAMWildcardActionRule(Rule):
    id = "IAM.1"
    severity = Severity.HIGH

    def check(self, session) -> list[Finding]:
        iam = session.client("iam")
        findings: list[Finding] = []

        # list_policies can return results across multiple pages once an
        # account has enough policies. get_paginator handles the
        # NextToken looping automatically instead of us tracking it by hand.
        # Scope="Local" limits this to customer-managed policies — the ones
        # the account owner actually wrote and can fix. AWS-managed
        # policies (Scope="AWS") aren't actionable findings for this tool.
        paginator = iam.get_paginator("list_policies")

        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                arn = policy["Arn"]

                try:
                    version = iam.get_policy_version(
                        PolicyArn=arn,
                        VersionId=policy["DefaultVersionId"],
                    )
                except ClientError:
                    continue

                document = version["PolicyVersion"]["Document"]
                statements = _as_list(document.get("Statement", []))

                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = _as_list(statement.get("Action", []))
                    resources = _as_list(statement.get("Resource", []))

                    if "*" in actions and "*" in resources:
                        findings.append(
                            Finding(
                                rule_id=self.id,
                                resource_id=arn,
                                severity=self.severity,
                                message=(
                                    f"IAM policy '{policy['PolicyName']}' grants "
                                    "'*' actions on '*' resources."
                                ),
                            )
                        )
                        break  # one finding per policy is enough

        return findings
