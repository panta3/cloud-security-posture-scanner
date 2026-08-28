terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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
}

# --- Alerting -------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "posture-scanner-alerts"
}

# TODO: aws_sns_topic_subscription for var.alert_email, once that's decided.

# --- Least-privilege role for the scanner itself --------------------------
# TODO: this is the important part to get right — read-only on every
# service the rules touch (s3, iam, ec2, rds), plus write access to
# the findings table and publish access to the alerts topic. Nothing else.
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

# TODO: aws_iam_role_policy attaching the least-privilege permissions above.

# --- The scanner Lambda ----------------------------------------------------
# TODO: packaging — this needs a zip/layer with boto3 + the scanner package.
# Leaving as a placeholder until the Lambda packaging story is decided.
#
# resource "aws_lambda_function" "scanner" {
#   function_name = "posture-scanner"
#   role          = aws_iam_role.scanner.arn
#   handler       = "lambda_handler.handler"
#   runtime       = "python3.12"
#   filename      = "../build/scanner.zip"
# }

# --- Schedule ---------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "posture-scanner-schedule"
  schedule_expression = var.scan_schedule
}

# TODO: aws_cloudwatch_event_target pointing at the Lambda, plus the
# aws_lambda_permission that lets EventBridge invoke it.
