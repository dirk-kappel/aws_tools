output "load_balancer_url" {
  description = "URL of the Application Load Balancer"
  value       = "http://${aws_lb.main.dns_name}"
}

output "codepipeline_name" {
  description = "Name of the Application CodePipeline"
  value       = aws_codepipeline.main.name
}

output "ami_codepipeline_name" {
  description = "Name of the AMI Update CodePipeline"
  value       = aws_codepipeline.ami_update.name
}

output "codebuild_project_name" {
  description = "Name of the Application CodeBuild project"
  value       = aws_codebuild_project.main.name
}

output "ami_codebuild_project_name" {
  description = "Name of the AMI CodeBuild project"
  value       = aws_codebuild_project.ami_build.name
}

output "codedeploy_application_name" {
  description = "Name of the CodeDeploy application"
  value       = aws_codedeploy_app.main.name
}

output "s3_artifacts_bucket" {
  description = "S3 bucket for Application Pipeline artifacts"
  value       = aws_s3_bucket.codepipeline_artifacts.bucket
}

output "s3_ami_artifacts_bucket" {
  description = "S3 bucket for AMI Pipeline artifacts"
  value       = aws_s3_bucket.ami_pipeline_artifacts.bucket
}

output "github_connection_arn" {
  description = "ARN of the GitHub connection (needs manual approval)"
  value       = aws_codestarconnections_connection.github.arn
}

output "auto_scaling_group_name" {
  description = "Name of the Auto Scaling Group"
  value       = aws_autoscaling_group.main.name
}

output "lambda_blue_green_function" {
  description = "Name of the Blue-Green deployment Lambda function"
  value       = aws_lambda_function.blue_green_deployment.function_name
}