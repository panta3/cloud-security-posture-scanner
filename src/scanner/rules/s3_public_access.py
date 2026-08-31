from botocore.exceptions import ClientError

from .base import Rule, Finding, Severity


class S3PublicAccessRule(Rule):
    id = "S3.1"
    severity = Severity.CRITICAL
    remediable = True

    def check(self, session) -> list[Finding]:
        s3 = session.client("s3")
        findings: list[Finding] = []

        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            name = bucket["Name"]

            if self._is_fully_blocked(s3, name):
                # Confirmed empirically, not just assumed: a bucket with
                # a public-looking policy attached but Block Public
                # Access fully enabled still reports get_bucket_policy_
                # status IsPublic=True — that call evaluates the policy
                # document itself, not whether the block is currently
                # neutralizing its real-world effect. Checking the block
                # config first is what actually reflects reality; this
                # is also exactly the state a remediated bucket ends up
                # in (see remediate() below), so getting this wrong would
                # mean a fixed bucket could never resolve.
                continue

            try:
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

    @staticmethod
    def _is_fully_blocked(s3, name: str) -> bool:
        try:
            block = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError:
            # No block configuration at all (the default, pre-2023-ish
            # state for older buckets) — nothing to neutralize a public
            # policy with, so this is not a "blocked" bucket.
            return False

        return all(
            block.get(key)
            for key in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )

    def remediate(self, session, resource_id: str) -> None:
        # Turns on all four Block Public Access settings. This doesn't
        # touch the bucket's actual ACL or policy documents — it just
        # makes AWS ignore any of them that would grant public access,
        # which is why it's safe to reverse: nothing gets deleted, the
        # block can be turned back off later if the public access was
        # somehow intentional.
        s3 = session.client("s3")
        s3.put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
