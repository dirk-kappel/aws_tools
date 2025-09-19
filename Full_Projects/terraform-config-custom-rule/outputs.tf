# outputs.tf

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.s3_config_rule.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.s3_config_rule.arn
}

output "config_rule_name" {
  description = "Name of the Config rule"
  value       = aws_config_config_rule.s3_classification_rule.name
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic"
  value       = aws_sns_topic.alerts.arn
}

output "test_commands" {
  description = "Commands to test the Config rule"
  value = {
    trigger_evaluation = "aws configservice start-config-rules-evaluation --config-rule-names ${aws_config_config_rule.s3_classification_rule.name}"
    check_compliance   = "aws configservice get-compliance-details-by-config-rule --config-rule-name ${aws_config_config_rule.s3_classification_rule.name}"
    view_logs          = "aws logs tail ${aws_cloudwatch_log_group.lambda_logs.name} --follow"
  }
}