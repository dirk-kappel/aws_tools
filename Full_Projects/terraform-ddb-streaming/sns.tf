# SNS Topic for message notifications
resource "aws_sns_topic" "message_notifications" {
  name = "message-notifications"

  # Optional: Enable encryption at rest
  kms_master_key_id = "alias/aws/sns"

  tags = {
    Name        = "MessageNotificationsTopic"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {}

# Email subscription example (you'll need to replace with your email)
resource "aws_sns_topic_subscription" "email_notification" {
  topic_arn = aws_sns_topic.message_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email # Will be defined in variables

  # Note: Email subscriptions require manual confirmation
}

# Optional: SQS subscription for testing/debugging
resource "aws_sqs_queue" "message_notifications_queue" {
  name = "message-notifications-queue"

  # Dead letter queue configuration
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.message_notifications_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name        = "MessageNotificationsQueue"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Dead letter queue for failed notifications
resource "aws_sqs_queue" "message_notifications_dlq" {
  name = "message-notifications-dlq"

  tags = {
    Name        = "MessageNotificationsDLQ"
    Environment = var.environment
    Project     = var.project_name
  }
}

# SQS subscription to SNS topic
resource "aws_sns_topic_subscription" "sqs_notification" {
  topic_arn = aws_sns_topic.message_notifications.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.message_notifications_queue.arn
}

# SQS Queue Policy to allow SNS to send messages
resource "aws_sqs_queue_policy" "message_notifications_queue_policy" {
  queue_url = aws_sqs_queue.message_notifications_queue.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSNSToSendMessage"
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action = [
          "sqs:SendMessage"
        ]
        Resource = aws_sqs_queue.message_notifications_queue.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.message_notifications.arn
          }
        }
      }
    ]
  })
}
