# Output values for easy reference and testing
output "primary_bucket_name" {
  description = "Name of the primary S3 bucket being monitored"
  value       = aws_s3_bucket.primary_bucket.bucket
}

output "cloudtrail_logs_bucket_name" {
  description = "Name of the S3 bucket storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs_bucket.bucket
}

output "cloudtrail_trail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.s3_trail.arn
}

output "lambda_function_name" {
  description = "Name of the Lambda function processing S3 events"
  value       = aws_lambda_function.s3_event_processor.function_name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for Lambda logs"
  value       = aws_cloudwatch_log_group.lambda_log_group.name
}

# Useful for testing
output "test_commands" {
  description = "Commands to test the setup"
  value = {
    upload_test_file     = "aws s3 cp test.txt s3://${aws_s3_bucket.primary_bucket.bucket}/"
    view_lambda_logs     = "aws logs tail ${aws_cloudwatch_log_group.lambda_log_group.name} --follow"
    view_cloudtrail_logs = "aws s3 ls s3://${aws_s3_bucket.cloudtrail_logs_bucket.bucket}/cloudtrail-logs/ --recursive"
  }
}