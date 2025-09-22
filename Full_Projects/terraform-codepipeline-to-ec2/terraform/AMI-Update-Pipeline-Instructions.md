# Pipeline 2 - AMI Update Pipeline with Blue-Green Deployment

## Overview

Pipeline 2 handles infrastructure updates by building new AMIs and performing zero-downtime blue-green deployments. This demonstrates how to update the underlying infrastructure (AMI) without affecting running applications.

## Architecture

**Pipeline 2 Flow:**
1. **Manual Trigger** → You manually start the pipeline
2. **Packer Build** → Creates new AMI with latest Amazon Linux and your application stack
3. **Manual Approval** → Review the new AMI before deployment
4. **Blue-Green Deploy** → Lambda function orchestrates zero-downtime infrastructure switch

## File Structure for Pipeline 2

Add these files to your repository:

```
terraform-codepipeline-to-ec2/
├── ami-pipeline/
│   ├── packer-template.pkr.hcl     # Packer template for AMI building
│   ├── ami-buildspec.yml           # CodeBuild instructions for AMI
│   └── blue-green-deployment.py    # Lambda function (created by Terraform)
└── terraform/
    ├── ami-pipeline.tf             # Pipeline 2 infrastructure
    └── (existing terraform files)
```

## Deployment Steps

### Step 1: Add Pipeline 2 Files

1. **Create ami-pipeline directory:**
   ```bash
   mkdir -p Full_Projects/terraform-codepipeline-to-ec2/ami-pipeline
   ```

2. **Add Packer template** - Copy `packer-template.pkr.hcl` to the ami-pipeline folder
3. **Add AMI buildspec** - Copy `ami-buildspec.yml` to the ami-pipeline folder
4. **Add Terraform file** - Copy `ami-pipeline.tf` to your terraform folder
5. **Update outputs** - Replace `outputs.tf` with the updated version

### Step 2: Deploy Pipeline 2 Infrastructure

```bash
cd Full_Projects/terraform-codepipeline-to-ec2/terraform
terraform apply
```

This creates:
- Second CodePipeline for AMI updates
- CodeBuild project configured for Packer
- Lambda function for blue-green deployment
- All necessary IAM roles and policies

### Step 3: Commit AMI Pipeline Files to GitHub

```bash
# From your repository root
git add Full_Projects/terraform-codepipeline-to-ec2/ami-pipeline/
git commit -m "Add AMI update pipeline with blue-green deployment"
git push origin main
```

### Step 4: Test Pipeline 2

1. **Go to AWS Console → CodePipeline**
2. **Find:** `codepipeline-learning-ami-pipeline`
3. **Click:** "Release change" to manually trigger the pipeline
4. **Monitor progress:**
   - **Source:** Pulls latest code
   - **BuildAMI:** Packer builds new AMI (takes ~10-15 minutes)
   - **ApprovalForDeployment:** Manual approval required
   - **BlueGreenDeploy:** Lambda orchestrates the deployment

## Blue-Green Deployment Process

**What happens during blue-green deployment:**

### Phase 1: Build Green Infrastructure
1. **New Launch Template Version** created with the new AMI
2. **Green Auto Scaling Group** created with new Launch Template
3. **Wait for Green instances** to pass health checks

### Phase 2: Traffic Switch
4. **Attach Green ASG** to Load Balancer Target Group
5. **Traffic begins flowing** to both Blue and Green instances
6. **Monitor for issues** during transition period

### Phase 3: Cleanup
7. **Detach Blue ASG** from Load Balancer
8. **Terminate Blue ASG** after connection draining
9. **Green becomes the new Blue** (primary infrastructure)

## Benefits of This Approach

✅ **Zero Downtime** - Traffic switches seamlessly between infrastructure  
✅ **Easy Rollback** - Can switch back to previous AMI if issues arise  
✅ **Infrastructure Updates** - Update base OS, security patches, system software  
✅ **Separation of Concerns** - App updates (Pipeline 1) vs Infrastructure updates (Pipeline 2)  

## When to Use Each Pipeline

### **Pipeline 1 (Application Updates):**
- Code changes in your web application
- Configuration updates
- Quick deployments (minutes)
- In-place updates via CodeDeploy

### **Pipeline 2 (Infrastructure Updates):**
- Operating system updates
- Security patches
- New system software installations
- Major infrastructure changes
- Slower deployments (15-30 minutes) but zero downtime

## Monitoring and Troubleshooting

### **Check AMI Build Progress:**
- AWS Console → CodeBuild → `codepipeline-learning-ami-build`
- Monitor Packer logs for AMI creation

### **Monitor Blue-Green Deployment:**
- AWS Console → Lambda → `codepipeline-learning-blue-green-deployment`
- Check CloudWatch logs for deployment progress
- Monitor Auto Scaling Groups during transition

### **Verify Successful Deployment:**
- Check your Load Balancer URL - should remain accessible throughout
- AWS Console → EC2 → Auto Scaling Groups - should see new instances
- AWS Console → EC2 → AMIs - should see newly created AMI

## Cost Considerations

**Pipeline 2 costs more than Pipeline 1:**
- **AMI builds:** ~10-15 minutes of EC2 instance time per build
- **Temporary infrastructure:** During blue-green deployment, you temporarily run 2x instances
- **Storage:** Each AMI creates additional EBS snapshots

**For learning:** Keep AMI builds infrequent and clean up unused AMIs periodically.

## Success Criteria

✅ **Manual trigger** starts Pipeline 2  
✅ **AMI builds successfully** with Packer  
✅ **Manual approval** works for infrastructure changes  
✅ **Blue-green deployment** completes without downtime  
✅ **Website remains accessible** throughout the entire process  
✅ **New infrastructure** serves traffic after deployment  

This completes your comprehensive CI/CD learning project with both application and infrastructure pipelines!