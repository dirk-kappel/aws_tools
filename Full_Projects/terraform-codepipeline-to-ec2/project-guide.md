# CodePipeline Learning Project - Specifications & Objects

## Project Goal
Create a minimal CI/CD pipeline using AWS CodePipeline with Terraform for learning purposes. Focus on simplicity and core concepts.

## Architecture Overview

### Pipeline 1: Application Deployment Pipeline
**Trigger:** GitHub webhook (automatic)
**Flow:** Source → Build → Manual Approval → Deploy

### Pipeline 2: AMI Update Pipeline  
**Trigger:** Manual
**Flow:** Build new AMI → Update Launch Template → Blue-Green Deployment

## Core Components & AWS Services

### 1. Source Code
- **GitHub Repository** containing:
  - Simple HTML/CSS web page (index.html)
  - Basic buildspec.yml for CodeBuild
  - appspec.yml for CodeDeploy

### 2. Pipeline 1 - Application Pipeline
- **CodePipeline** (main pipeline)
- **Source Stage:** GitHub integration
- **Build Stage:** CodeBuild project
- **Approval Stage:** Manual approval action
- **Deploy Stage:** CodeDeploy application

### 3. Pipeline 2 - AMI Update Pipeline
- **CodePipeline** (AMI pipeline) 
- **Build Stage:** Packer build via CodeBuild
- **Deploy Stage:** Update Auto Scaling Group

### 4. Compute Infrastructure
- **EC2 Instance(s)** running web server
- **Auto Scaling Group** (min: 1, max: 2)
- **Application Load Balancer**
- **Launch Template** (for consistent instance creation)

### 5. Supporting Infrastructure
- **S3 Buckets:**
  - CodePipeline artifacts
  - Web content deployment
- **IAM Roles & Policies:**
  - CodePipeline execution role
  - CodeBuild service role  
  - CodeDeploy service role
  - EC2 instance profile
- **Security Groups:**
  - ALB security group (port 80)
  - EC2 security group (port 80 from ALB)

## Terraform Resource Structure

### Core Infrastructure (`main.tf`)
- VPC with public subnets
- Internet Gateway and routing
- Security Groups
- Application Load Balancer
- Auto Scaling Group & Launch Template

### CodePipeline Resources (`pipeline.tf`)
- S3 bucket for artifacts
- CodePipeline (application pipeline)
- CodeBuild project
- CodeDeploy application & deployment group

### AMI Pipeline Resources (`ami-pipeline.tf`)
- CodePipeline (AMI update pipeline)
- CodeBuild project for Packer
- Lambda function for ASG update

### IAM Resources (`iam.tf`)
- All required roles and policies
- Instance profile for EC2

## Minimal File Structure
```
terraform/
├── main.tf                 # Core infrastructure
├── pipeline.tf             # Application pipeline
├── ami-pipeline.tf         # AMI update pipeline  
├── iam.tf                  # IAM roles and policies
├── variables.tf            # Input variables
├── outputs.tf              # Output values
└── terraform.tfvars       # Variable values

sample-app/
├── index.html             # Simple web page
├── buildspec.yml          # CodeBuild instructions
├── appspec.yml            # CodeDeploy instructions
└── scripts/
    └── install.sh         # Deployment script
```

## Key Learning Concepts Covered
1. **CodePipeline:** Multi-stage automation
2. **CodeBuild:** Build and test automation  
3. **CodeDeploy:** Application deployment
4. **Infrastructure as Code:** Terraform
5. **Blue-Green Deployment:** AMI updates
6. **Manual Approvals:** Controlled deployments
7. **Webhook Integration:** GitHub triggers

## Deployment Strategy
- **Application Updates:** In-place deployment via CodeDeploy
- **AMI Updates:** Blue-green via Auto Scaling Group replacement
- **Rollback:** Manual via AWS Console or Terraform

## Success Criteria
1. Code push to GitHub triggers Pipeline 1
2. Manual approval gate works
3. Web page deploys successfully to EC2
4. AMI pipeline updates infrastructure
5. Zero-downtime deployment for AMI changes