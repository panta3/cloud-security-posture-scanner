output "findings_table_name" {
  value = aws_dynamodb_table.findings.name
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.scanner.function_name
}

output "schedule_expression" {
  value = aws_cloudwatch_event_rule.schedule.schedule_expression
}
