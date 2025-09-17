# Lambda function to process S3 events
resource "aws_lambda_function" "s3_event_processor" {
  filename      = "s3_event_processor.zip"
  function_name = "s3-event-processor"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  timeout       = 30

  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL = "INFO"
      S3_BUCKET = aws_s3_bucket.primary_bucket.bucket
    }
  }

  tags = {
    Name        = "S3 Event Processor"
    Environment = "sandbox"
    Purpose     = "s3-event-logging"
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_policy_attachment,
    aws_cloudwatch_log_group.lambda_log_group
  ]
}

# Create zip file from Python code
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "s3_event_processor.zip"
  source {
    content  = file("lambda_function.py")
    filename = "index.py"
  }
}