variable "aws_region" {
  description = "Region to deploy the scanner infra into"
  type        = string
  default     = "us-east-1"
}

variable "scan_schedule" {
  description = "EventBridge schedule expression for how often the scanner runs"
  type        = string
  default     = "rate(1 day)"
}

variable "alert_email" {
  description = "Email subscribed to the SNS topic for Critical/High findings"
  type        = string
  default     = ""
}

variable "auto_remediate_rules" {
  description = "Comma-separated CIS rule IDs to auto-remediate (e.g. \"S3.1,RDS.1\"). Empty by default — remediation is opt-in, not automatic."
  type        = string
  default     = ""
}
