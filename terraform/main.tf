terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Findings storage ---------------------------------------------------
resource "aws_dynamodb_table" "findings" {
  name         = "posture-scanner-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # RESOLVED findings get a 30-day expires_at (see notify.py) so they
  # clean up automatically instead of accumulating forever. ACTIVE
  # findings never get expires_at set, so they're never auto-deleted.
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

# --- Alerting -------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "posture-scanner-alerts"
}

resource "aws_sns_topic_subscription" "alert_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Least-privilege role for the scanner itself --------------------------
# Read-only on every service the rules touch (s3, iam, ec2, rds), plus
# write access to the findings table and publish access to the alerts
# topic. Nothing else — the scanner should never be able to modify what
# it's auditing.
resource "aws_iam_role" "scanner" {
  name = "posture-scanner-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "scanner_permissions" {
  name = "posture-scanner-permissions"
  role = aws_iam_role.scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyAudit"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "iam:ListPolicies",
          "iam:GetPolicyVersion",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "rds:DescribeDBInstances",
        ]
        Resource = "*"
        # These are all read-only, account-wide describe/list calls with
        # no resource-level ARN support in IAM — "*" is correct here, not
        # a shortcut. Scoping comes from the action list, not the resource.
      },
      {
        Sid    = "Remediation"
        Effect = "Allow"
        # Deliberately narrow and kept as its own statement, separate
        # from ReadOnlyAudit, so it's obvious at a glance that these two
        # permissions are the entire "can actually change something"
        # surface — matches exactly the two remediate() implementations
        # in rules/s3_public_access.py and rules/rds_public.py. Nothing
        # here can delete a resource or touch IAM/security groups.
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "rds:ModifyDBInstance",
        ]
        Resource = "*"
      },
      {
        Sid      = "WriteFindings"
        Effect   = "Allow"
        # Scan: needed to find previously-ACTIVE findings to diff against
        # the current scan (see notify.py). UpdateItem replaced PutItem
        # once findings became upserts keyed by rule_id#resource_id
        # instead of one-shot writes keyed by a random UUID.
        Action   = ["dynamodb:Scan", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.findings.arn
      },
      {
        Sid      = "PublishAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid      = "LambdaLogging"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Sid    = "PublishMetrics"
        Effect = "Allow"
        Action = ["cloudwatch:PutMetricData"]
        # PutMetricData doesn't support resource-level restriction —
        # AWS requires "*" here regardless of how narrow you want to be.
        Resource = "*"
      },
    ]
  })
}

# --- The scanner Lambda ----------------------------------------------------
# boto3 ships with the Lambda Python runtime already — the zip only needs
# our own code (lambda_handler.py + the scanner package), which is why
# lambda_handler.py lives in src/ alongside scanner/: source_dir zips
# whatever's in that one directory, so they need to sit together.
data "archive_file" "scanner_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/build/scanner.zip"
  excludes    = ["scanner.egg-info", "__pycache__"]
}

resource "aws_lambda_function" "scanner" {
  function_name    = "posture-scanner"
  role              = aws_iam_role.scanner.arn
  handler           = "lambda_handler.handler"
  runtime           = "python3.12"
  timeout           = 60
  # Default 128MB hit its ceiling on one run and the invocation timed out
  # with no error logged (likely GC/network thrashing under memory
  # pressure) — Lambda scales CPU with memory, so this buys both.
  memory_size       = 256
  filename          = data.archive_file.scanner_zip.output_path
  source_code_hash  = data.archive_file.scanner_zip.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE_NAME  = aws_dynamodb_table.findings.name
      ALERTS_TOPIC_ARN     = aws_sns_topic.alerts.arn
      AUTO_REMEDIATE_RULES = var.auto_remediate_rules
    }
  }
}

# --- Schedule ---------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "posture-scanner-schedule"
  schedule_expression = var.scan_schedule
}

resource "aws_cloudwatch_event_target" "scanner" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# --- Observability -----------------------------------------------------
# Domain-specific metrics (findings, severity breakdown, remediation)
# come from scanner/metrics.py, published on every invoke. Lambda's own
# Duration/Errors/Invocations metrics are free — no code needed for
# those, just referencing the AWS/Lambda namespace below.
resource "aws_cloudwatch_dashboard" "scanner" {
  dashboard_name = "posture-scanner"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 1
        properties = {
          markdown = "# Posture Scanner — Operational Dashboard"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 1
        width  = 12
        height = 6
        properties = {
          title  = "Scan Duration"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Average"
          period = 86400
          metrics = [
            ["PostureScanner", "ScanDuration"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 1
        width  = 12
        height = 6
        properties = {
          title  = "Findings — Total / New / Remediated"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Maximum"
          period = 86400
          metrics = [
            ["PostureScanner", "TotalFindings"],
            ["PostureScanner", "NewFindings"],
            ["PostureScanner", "RemediatedFindings"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 7
        width  = 12
        height = 6
        properties = {
          title  = "Findings by Severity"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Maximum"
          period = 86400
          metrics = [
            ["PostureScanner", "FindingsBySeverity", "Severity", "CRITICAL"],
            ["PostureScanner", "FindingsBySeverity", "Severity", "HIGH"],
            ["PostureScanner", "FindingsBySeverity", "Severity", "MEDIUM"],
            ["PostureScanner", "FindingsBySeverity", "Severity", "LOW"],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 7
        width  = 12
        height = 6
        properties = {
          title  = "Lambda Health (built-in, no custom code)"
          region = var.aws_region
          view   = "timeSeries"
          stat   = "Sum"
          period = 86400
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", aws_lambda_function.scanner.function_name],
            ["AWS/Lambda", "Errors", "FunctionName", aws_lambda_function.scanner.function_name],
          ]
        }
      },
    ]
  })
}
