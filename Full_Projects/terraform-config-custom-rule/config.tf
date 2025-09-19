# config.tf

# AWS Config Rule
resource "aws_config_config_rule" "s3_classification_rule" {
  name = "${var.project_name}-rule"

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.s3_config_rule.arn

    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
  }

  input_parameters = jsonencode({
    requiredTags         = var.required_tags
    validClassifications = var.valid_classifications
    namingPattern        = var.naming_pattern
  })

  depends_on = [aws_lambda_permission.config_invoke]
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

# Email subscription (if email provided)
resource "aws_sns_topic_subscription" "email" {
  count     = var.notification_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# CloudWatch alarm for Lambda errors
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${var.project_name}-lambda-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Lambda function errors"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    FunctionName = aws_lambda_function.s3_config_rule.function_name
  }
}