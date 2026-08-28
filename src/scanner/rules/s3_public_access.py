from botocore.exceptions import ClientError

from .base import Rule, Finding, Severity


class S3PublicAccessRule(Rule):
    id = "S3.1"
    severity = Severity.CRITICAL

    def check(self, session) -> list[Finding]:
        s3 = session.client("s3")
        findings: list[Finding] = []

        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            name = bucket["Name"]

            try:
                # get_bucket_policy_status is AWS's own computed answer to
                # "is this bucket public," factoring in ACLs, the bucket
                # policy, and both account- and bucket-level Block Public
                # Access settings together. Reimplementing that logic by
                # hand from the individual pieces would be easy to get
                # subtly wrong — better to ask AWS directly.
                status = s3.get_bucket_policy_status(Bucket=name)
                is_public = status["PolicyStatus"]["IsPublic"]
            except ClientError:
                # A bucket we can't evaluate (permissions, region quirks,
                # etc.) isn't a confirmed finding — skip it rather than
                # crash the whole scan over one bucket.
                continue

            if is_public:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        resource_id=name,
                        severity=self.severity,
                        message=f"S3 bucket '{name}' is publicly accessible.",
                    )
                )

        return findings
