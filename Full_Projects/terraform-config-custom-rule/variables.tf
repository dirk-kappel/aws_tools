# variables.tf

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "s3-classification-config"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "required_tags" {
  description = "Required tags for S3 buckets"
  type        = list(string)
  default     = ["DataClassification", "Owner"]
}

variable "valid_classifications" {
  description = "Valid data classification values"
  type        = list(string)
  default     = ["public", "internal", "confidential", "restricted"]
}

variable "naming_pattern" {
  description = "Regex pattern for bucket naming"
  type        = string
  default     = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 300
}

variable "notification_email" {
  description = "Email for notifications"
  type        = string
  default     = ""
}