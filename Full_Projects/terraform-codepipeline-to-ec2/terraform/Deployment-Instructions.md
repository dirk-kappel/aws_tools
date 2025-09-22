# Terraform Deployment Instructions

## Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **Terraform installed** (version >= 1.0)
3. **GitHub repository** with your application code pushed

## File Structure

Your directory structure should look like this (which you already have):

```
terraform-codepipeline-to-ec2/
├── sample-app/
│   ├── index.html
│   ├── buildspec.yml
│   ├── appspec.yml
│   └── scripts/
│       ├── install_dependencies.sh
│       ├── start_server.sh
│       └── stop_server.sh
└── terraform/
    ├── main.tf
    ├── variables.tf  
    ├── iam.tf
    ├── pipeline.tf
    ├── outputs.tf
    ├── terraform.tfvars
    └── user_data.sh
```

## Step-by-Step Deployment

### Step 1: Initialize Terraform

```bash
cd Full_Projects/terraform-codepipeline-to-ec2/terraform
terraform init
```

### Step 2: Plan the Deployment

```bash
# Make sure you're in the terraform directory
cd Full_Projects/terraform-codepipeline-to-ec2/terraform
terraform plan
```

Review the planned resources. You should see:
- VPC with subnets and networking
- Application Load Balancer
- Auto Scaling Group with Launch Template  
- CodePipeline, CodeBuild, and CodeDeploy resources
- IAM roles and policies
- S3 bucket for artifacts

### Step 3: Apply the Configuration

```bash
terraform apply
```

Type `yes` when prompted to confirm.

### Step 4: **CRITICAL** - Approve GitHub Connection

After terraform completes, you'll see output including a `github_connection_arn`. 

**You MUST manually approve this connection:**

1. Go to AWS Console → CodePipeline → Settings → Connections
2. Find the connection named `codepipeline-learning-github`
3. Click on it and select **"Update pending connection"**
4. Follow the prompts to authorize GitHub access
5. The status should change from "Pending" to "Available"

### Step 5: Test the Pipeline

1. **Check your Load Balancer URL:**
   ```bash
   terraform output load_balancer_url
   ```
   
2. **Visit the URL** - you should see "Server Ready - Waiting for Deployment"

3. **Trigger the Pipeline:**
   - Make a small change to your `index.html` file (e.g., update the version)
   - Commit and push to GitHub
   - Go to AWS Console → CodePipeline to watch the pipeline execute

4. **Approve the Deployment:**
   - The pipeline will pause at the "Approval" stage
   - Click "Review" and approve the deployment
   - Watch the deployment complete

5. **Verify the Result:**
   - Refresh your Load Balancer URL
   - You should see your updated web page

## Important Notes

### Buildspec Location
The buildspec.yml path is configured as `Full_Projects/terraform-codepipeline-to-ec2/buildspec.yml` relative to your repository root. Make sure this matches your actual file location.

### CodeDeploy Agent
The EC2 instances will automatically install the CodeDeploy agent via the user_data script. This takes a few minutes after instance launch.

### Costs
This setup uses:
- 1 t2.micro EC2 instance (free tier eligible)
- Application Load Balancer (~$16-20/month)
- Small amounts of S3, CodePipeline usage

### Cleanup
When you're done learning, clean up resources:
```bash
terraform destroy
```

## Troubleshooting

### Pipeline Fails on First Run
- Check that GitHub connection is approved
- Verify buildspec.yml path is correct
- Check CodeBuild logs in AWS Console

### Deployment Fails  
- Verify EC2 instances have CodeDeploy agent installed
- Check Auto Scaling Group has healthy instances
- Review CodeDeploy deployment logs

### Can't Access Web Page
- Check security groups allow HTTP traffic
- Verify instances are healthy in Target Group
- Check Apache is running on instances

## Success Criteria

✅ **Pipeline triggers automatically** when you push to GitHub  
✅ **Manual approval step** works correctly  
✅ **Web page deploys** and is accessible via Load Balancer URL  
✅ **Updates deploy successfully** when you change the code  

Once this is working, you're ready to move on to Pipeline 2 (AMI updates)!