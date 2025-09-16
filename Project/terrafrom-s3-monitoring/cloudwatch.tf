# CloudWatch Log Group for Lambda function logs
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/s3-event-processor"
  retention_in_days = 14

  tags = {
    Name        = "S3 Event Processor Logs"
    Environment = "sandbox"
    Purpose     = "lambda-logging"
  }
}

# CloudWatch Logs subscription filter to trigger Lambda
resource "aws_cloudwatch_log_subscription_filter" "s3_events_filter" {
  name            = "s3-api-events-filter"
  log_group_name  = aws_cloudwatch_log_group.cloudtrail_logs.name
  filter_pattern  = "{$.eventName=PutObject || $.eventName=GetObject || $.eventName=DeleteObject}"
  destination_arn = aws_lambda_function.s3_event_processor.arn

  depends_on = [aws_lambda_permission.allow_cloudwatch_logs]
}

# Lambda permission for CloudWatch Logs
resource "aws_lambda_permission" "allow_cloudwatch_logs" {
  statement_id  = "AllowExecutionFromCloudWatchLogs"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_event_processor.function_name
  principal     = "logs.${data.aws_region.current.name}.amazonaws.com"
  source_arn    = "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
}