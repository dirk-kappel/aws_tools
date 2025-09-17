# Output the table details for reference
output "dynamodb_table_name" {
  description = "Name of the DynamoDB messages table"
  value       = aws_dynamodb_table.messages.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB messages table"
  value       = aws_dynamodb_table.messages.arn
}

output "dynamodb_stream_arn" {
  description = "ARN of the DynamoDB stream"
  value       = aws_dynamodb_table.messages.stream_arn
}

output "dynamodb_stream_label" {
  description = "Timestamp-based label of the DynamoDB stream"
  value       = aws_dynamodb_table.messages.stream_label
}

# Outputs for reference by other resources
output "sns_topic_arn" {
  description = "ARN of the SNS topic for message notifications"
  value       = aws_sns_topic.message_notifications.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic"
  value       = aws_sns_topic.message_notifications.name
}

output "sqs_queue_url" {
  description = "URL of the SQS queue for testing notifications"
  value       = aws_sqs_queue.message_notifications_queue.url
}

output "sqs_queue_arn" {
  description = "ARN of the SQS queue"
  value       = aws_sqs_queue.message_notifications_queue.arn
}

# Outputs
output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.message_processor.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.message_processor.arn
}

output "lambda_log_group_name" {
  description = "CloudWatch log group name for Lambda function"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}