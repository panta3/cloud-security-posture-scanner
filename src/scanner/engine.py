import boto3

from scanner.rules.base import Finding, Rule
from scanner.rules.s3_public_access import S3PublicAccessRule
from scanner.rules.iam_wildcard import IAMWildcardActionRule
from scanner.rules.security_group_open import OpenSecurityGroupRule
from scanner.rules.rds_public import RDSPubliclyAccessibleRule
from scanner.rules.ebs_unencrypted import EBSUnencryptedRule

# Registering a rule here is the only wiring a new check needs.
ALL_RULES: list[Rule] = [
    S3PublicAccessRule(),
    IAMWildcardActionRule(),
    OpenSecurityGroupRule(),
    RDSPubliclyAccessibleRule(),
    EBSUnencryptedRule(),
]


def run_scan(profile: str | None = None, region: str | None = None) -> list[Finding]:
    session = boto3.Session(profile_name=profile, region_name=region)
    findings: list[Finding] = []

    for rule in ALL_RULES:
        # TODO: decide how a single failing rule should behave —
        # currently one broken rule kills the whole scan, which is
        # probably too fragile once more rules exist.
        findings.extend(rule.check(session))

    return findings
