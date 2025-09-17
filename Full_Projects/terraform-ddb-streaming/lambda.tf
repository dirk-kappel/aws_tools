# Create a ZIP file of the Lambda function code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/lambda_function.py"
  output_path = "${path.module}/lambda_function.zip"
}

# IAM role for Lambda function
resource "aws_iam_role" "lambda_execution_role" {
  name = "message-processor-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "MessageProcessorLambdaRole"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Basic Lambda execution policy (for CloudWatch Logs)
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_execution_role.name
}

# DynamoDB Streams read policy
resource "aws_iam_role_policy" "lambda_dynamodb_streams_policy" {
  name = "lambda-dynamodb-streams-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeStream",
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:ListStreams"
        ]
        Resource = [
          aws_dynamodb_table.messages.stream_arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.messages.arn,
          "${aws_dynamodb_table.messages.arn}/index/*"
        ]
      }
    ]
  })
}

# SNS publish policy
resource "aws_iam_role_policy" "lambda_sns_policy" {
  name = "lambda-sns-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.message_notifications.arn
        ]
      }
    ]
  })
}

# Lambda function
resource "aws_lambda_function" "message_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "message-stream-processor"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.messages.name
      SNS_TOPIC_ARN       = aws_sns_topic.message_notifications.arn
    }
  }

  # Dead letter queue for failed invocations
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tags = {
    Name        = "MessageStreamProcessor"
    Environment = var.environment
    Project     = var.project_name
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic_execution,
    aws_iam_role_policy.lambda_dynamodb_streams_policy,
    aws_iam_role_policy.lambda_sns_policy,
    aws_cloudwatch_log_group.lambda_logs
  ]
}

# CloudWatch log group for Lambda function
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/message-stream-processor"
  retention_in_days = 7 # Keep logs for 7 days for learning purposes

  tags = {
    Name        = "MessageProcessorLambdaLogs"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Dead letter queue for Lambda function failures
resource "aws_sqs_queue" "lambda_dlq" {
  name = "message-processor-dlq"

  tags = {
    Name        = "MessageProcessorDLQ"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Event source mapping to connect DynamoDB stream to Lambda
resource "aws_lambda_event_source_mapping" "dynamodb_stream_trigger" {
  event_source_arn  = aws_dynamodb_table.messages.stream_arn
  function_name     = aws_lambda_function.message_processor.arn
  starting_position = "LATEST" # Only process new records

  # Batch configuration
  batch_size                         = 10 # Process up to 10 records at once
  maximum_batching_window_in_seconds = 5  # Wait max 5 seconds to batch records

  # Error handling
  maximum_retry_attempts        = 3
  maximum_record_age_in_seconds = 3600 # Discard records older than 1 hour

  # Send failed records to DLQ after max retries
  destination_config {
    on_failure {
      destination_arn = aws_sqs_queue.lambda_dlq.arn
    }
  }
}

# Additional IAM policy for Lambda to send failed records to DLQ
resource "aws_iam_role_policy" "lambda_dlq_policy" {
  name = "lambda-dlq-policy"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:SendMessage"
        ]
        Resource = [
          aws_sqs_queue.lambda_dlq.arn
        ]
      }
    ]
  })
}
