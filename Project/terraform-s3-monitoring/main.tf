# Data sources for current AWS account and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}