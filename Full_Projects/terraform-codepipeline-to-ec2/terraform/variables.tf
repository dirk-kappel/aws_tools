variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "codepipeline-learning"
}

variable "github_owner" {
  description = "GitHub repository owner"
  type        = string
  default     = "dirk-kappel"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "aws_tools"
}

variable "github_branch" {
  description = "GitHub branch"
  type        = string
  default     = "main"
}

variable "source_location" {
  description = "Source location within the repository"
  type        = string
  default     = "Full_Projects/terraform-codepipeline-to-ec2"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "min_size" {
  description = "Minimum number of instances in ASG"
  type        = number
  default     = 1
}

variable "max_size" {
  description = "Maximum number of instances in ASG"
  type        = number
  default     = 2
}

variable "desired_capacity" {
  description = "Desired number of instances in ASG"
  type        = number
  default     = 1
}