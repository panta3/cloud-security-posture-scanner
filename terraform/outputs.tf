output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
