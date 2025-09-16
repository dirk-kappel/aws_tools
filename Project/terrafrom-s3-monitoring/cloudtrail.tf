# CloudWatch Log Group for CloudTrail
resource "aws_cloudwatch_log_group" "cloudtrail_logs" {
  name              = "cloudtrail-s3-api-logs"
  retention_in_days = 14

  tags = {
    Name        = "CloudTrail S3 API Logs"
    Environment = "sandbox"
    Purpose     = "cloudtrail-api-logging"
  }
}

# IAM role for CloudTrail to write to CloudWatch Logs
resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name = "cloudtrail-cloudwatch-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

# Enhanced IAM policy with validation permissions
resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name = "cloudtrail-cloudwatch-logs-policy"
  role = aws_iam_role.cloudtrail_cloudwatch_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailLogsPolicy"
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = [
          aws_cloudwatch_log_group.cloudtrail_logs.arn,
          "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
        ]
      },
      {
        Sid    = "AWSCloudTrailLogsValidation"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# Updated CloudTrail configuration
resource "aws_cloudtrail" "s3_trail" {
  name           = "s3-monitoring-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs_bucket.bucket
  s3_key_prefix  = "cloudtrail-logs"

  # Add CloudWatch Logs configuration
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_logs.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch_role.arn

  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true

  # S3 Data Events
  advanced_event_selector {
    name = "S3 Data Events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.primary_bucket.arn}/"]
    }
  }

  tags = {
    Name        = "S3 Monitoring Trail"
    Environment = "sandbox"
    Purpose     = "s3-api-monitoring"
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs_policy,
    aws_iam_role_policy.cloudtrail_cloudwatch_policy,
    aws_cloudwatch_log_group.cloudtrail_logs
  ]
}