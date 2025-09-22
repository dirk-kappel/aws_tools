# S3 Bucket for AMI Pipeline artifacts (separate from main pipeline)
resource "aws_s3_bucket" "ami_pipeline_artifacts" {
  bucket        = "${var.project_name}-ami-pipeline-artifacts-${random_id.ami_bucket_suffix.hex}"
  force_destroy = true

  tags = {
    Name = "${var.project_name}-ami-pipeline-artifacts"
  }
}

resource "aws_s3_bucket_versioning" "ami_pipeline_artifacts" {
  bucket = aws_s3_bucket.ami_pipeline_artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ami_pipeline_artifacts" {
  bucket = aws_s3_bucket.ami_pipeline_artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "random_id" "ami_bucket_suffix" {
  byte_length = 8
}

# CodeBuild Project for AMI Building with Packer
resource "aws_codebuild_project" "ami_build" {
  name         = "${var.project_name}-ami-build"
  description  = "Build AMI using Packer for ${var.project_name}"
  service_role = aws_iam_role.ami_codebuild_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
  }

  source {
    type      = "CODEPIPELINE"
    buildspec = "Full_Projects/terraform-codepipeline-to-ec2/ami-pipeline/ami-buildspec.yml"
  }

  tags = {
    Name = "${var.project_name}-ami-build"
  }
}

# Lambda function for Blue-Green deployment
resource "aws_lambda_function" "blue_green_deployment" {
  filename         = "blue_green_deployment.zip"
  function_name    = "${var.project_name}-blue-green-deployment"
  role             = aws_iam_role.lambda_blue_green_role.arn
  handler          = "blue-green-deployment.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.9"
  timeout          = 900 # 15 minutes for deployment process

  tags = {
    Name = "${var.project_name}-blue-green-lambda"
  }
}

# Create Lambda deployment package
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "blue_green_deployment.zip"
  source {
    content  = file("../ami-pipeline/blue-green-deployment.py")
    filename = "blue-green-deployment.py"
  }
}

# AMI Update Pipeline (Pipeline 2)
resource "aws_codepipeline" "ami_update" {
  name     = "${var.project_name}-ami-pipeline"
  role_arn = aws_iam_role.ami_codepipeline_role.arn

  artifact_store {
    location = aws_s3_bucket.ami_pipeline_artifacts.bucket
    type     = "S3"
  }

  stage {
    name = "Source"

    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "CodeStarSourceConnection"
      version          = "1"
      output_artifacts = ["ami_source_output"]

      configuration = {
        ConnectionArn    = aws_codestarconnections_connection.github.arn
        FullRepositoryId = "${var.github_owner}/${var.github_repo}"
        BranchName       = var.github_branch
      }
    }
  }

  stage {
    name = "BuildAMI"

    action {
      name             = "BuildAMI"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["ami_source_output"]
      output_artifacts = ["ami_build_output"]
      version          = "1"

      configuration = {
        ProjectName = aws_codebuild_project.ami_build.name
      }
    }
  }

  stage {
    name = "ApprovalForDeployment"

    action {
      name     = "ApprovalForDeployment"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"

      configuration = {
        CustomData = "Please review the new AMI and approve blue-green deployment to production infrastructure."
      }
    }
  }

  stage {
    name = "BlueGreenDeploy"

    action {
      name            = "BlueGreenDeploy"
      category        = "Invoke"
      owner           = "AWS"
      provider        = "Lambda"
      input_artifacts = ["ami_build_output"]
      version         = "1"

      configuration = {
        FunctionName = aws_lambda_function.blue_green_deployment.function_name
      }
    }
  }

  tags = {
    Name = "${var.project_name}-ami-pipeline"
  }
}

# IAM Role for AMI CodeBuild
resource "aws_iam_role" "ami_codebuild_role" {
  name = "${var.project_name}-ami-codebuild-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ami-codebuild-role"
  }
}

# IAM Policy for AMI CodeBuild (includes Packer permissions)
resource "aws_iam_role_policy" "ami_codebuild_policy" {
  name = "${var.project_name}-ami-codebuild-policy"
  role = aws_iam_role.ami_codebuild_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.ami_pipeline_artifacts.arn,
          "${aws_s3_bucket.ami_pipeline_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CopyImage",
          "ec2:CreateImage",
          "ec2:CreateKeypair",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteKeyPair",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSnapshot",
          "ec2:DeleteVolume",
          "ec2:DeregisterImage",
          "ec2:DescribeImageAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeSubnets",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DetachVolume",
          "ec2:GetPasswordData",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:RegisterImage",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Role for AMI CodePipeline
resource "aws_iam_role" "ami_codepipeline_role" {
  name = "${var.project_name}-ami-codepipeline-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "codepipeline.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ami-codepipeline-role"
  }
}

# IAM Policy for AMI CodePipeline
resource "aws_iam_role_policy" "ami_codepipeline_policy" {
  name = "${var.project_name}-ami-codepipeline-policy"
  role = aws_iam_role.ami_codepipeline_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:GetBucketVersioning"
        ]
        Resource = [
          aws_s3_bucket.ami_pipeline_artifacts.arn,
          "${aws_s3_bucket.ami_pipeline_artifacts.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "codebuild:BatchGetBuilds",
          "codebuild:StartBuild"
        ]
        Resource = aws_codebuild_project.ami_build.arn
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = aws_lambda_function.blue_green_deployment.arn
      },
      {
        Effect = "Allow"
        Action = [
          "codestar-connections:UseConnection"
        ]
        Resource = aws_codestarconnections_connection.github.arn
      }
    ]
  })
}

# IAM Role for Lambda Blue-Green Deployment
resource "aws_iam_role" "lambda_blue_green_role" {
  name = "${var.project_name}-lambda-blue-green-role"

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
    Name = "${var.project_name}-lambda-blue-green-role"
  }
}

# IAM Policy for Lambda Blue-Green Deployment
resource "aws_iam_role_policy" "lambda_blue_green_policy" {
  name = "${var.project_name}-lambda-blue-green-policy"
  role = aws_iam_role.lambda_blue_green_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateLaunchTemplateVersion",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:CreateAutoScalingGroup",
          "autoscaling:DeleteAutoScalingGroup",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:UpdateAutoScalingGroup",
          "autoscaling:AttachLoadBalancerTargetGroups",
          "autoscaling:DetachLoadBalancerTargetGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "codepipeline:PutJobSuccessResult",
          "codepipeline:PutJobFailureResult"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = [
          aws_s3_bucket.ami_pipeline_artifacts.arn,
          "${aws_s3_bucket.ami_pipeline_artifacts.arn}/*"
        ]
      }
    ]
  })
}