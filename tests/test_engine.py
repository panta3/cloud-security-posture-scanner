# TODO: real tests once rules are implemented. Suggestion: use `moto` to
# mock AWS responses rather than hitting a real account in CI.
#
# Example shape once a rule is implemented:
#
# @mock_aws
# def test_s3_public_access_flags_public_bucket():
#     ...create a bucket with public access via boto3...
#     findings = S3PublicAccessRule().check(session)
#     assert len(findings) == 1

def test_placeholder():
    assert True
