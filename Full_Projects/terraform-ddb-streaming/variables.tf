variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

# Variables for configuration
variable "notification_email" {
  description = "Email address to receive message notifications"
  type        = string
  default     = "your-email@example.com" # Update this with your email
}

# Variables for consistency
variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "learning"
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "dynamodb-streaming-triggers"
}