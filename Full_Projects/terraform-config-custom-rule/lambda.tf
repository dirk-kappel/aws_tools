# lambda.tf

# IAM Role for Lambda
resource "aws_iam_role" "config_lambda_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.config_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Custom policy for Config and S3
resource "aws_iam_role_policy" "config_lambda_policy" {
  name = "${var.project_name}-lambda-policy"
  role = aws_iam_role.config_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "config:PutEvaluations",
          "config:GetComplianceDetailsByConfigRule"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketTagging",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketPublicAccessBlock",
          "s3:ListBucket",
          "s3:HeadBucket",
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Create Lambda function code archive
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda-function.zip"

  source {
    content  = file("${path.module}/lambda_function.py")
    filename = "lambda_function.py"
  }
}

# Lambda function
resource "aws_lambda_function" "s3_config_rule" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-lambda"
  role             = aws_iam_role.config_lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  timeout          = var.lambda_timeout
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      PROJECT_NAME = var.project_name
    }
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.s3_config_rule.function_name}"
  retention_in_days = 14
}

# Permission for Config to invoke Lambda
resource "aws_lambda_permission" "config_invoke" {
  statement_id  = "AllowConfigInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_config_rule.function_name
  principal     = "config.amazonaws.com"
}