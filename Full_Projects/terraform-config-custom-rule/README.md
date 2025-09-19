# AWS Config Custom Rule: S3 Data Classification Compliance

A simple AWS Config custom rule that enforces data classification policies on S3 buckets. This project demonstrates how to create, deploy, and test custom Config rules using Terraform and AWS Lambda.

## 🎯 What This Rule Checks

This custom Config rule evaluates S3 buckets for compliance with organizational data classification policies:

- ✅ **Bucket Naming Convention**: Ensures bucket names follow your regex pattern (default: lowercase alphanumeric with hyphens)
- ✅ **Required Tags**: Validates that mandatory tags are present (default: `DataClassification` and `Owner`)
- ✅ **Valid Classifications**: Ensures data classification values are from approved list (default: `public`, `internal`, `confidential`, `restricted`)
- ✅ **Security Controls**: For sensitive data (`confidential`/`restricted`):
  - Server-side encryption must be enabled
  - Public access must be fully blocked

## 📁 Project Structure

```
s3-classification-config/
├── providers.tf          # Terraform and AWS provider configuration
├── variables.tf          # Variable declarations
├── lambda.tf             # Lambda function and IAM resources
├── config.tf             # AWS Config rule and monitoring
├── outputs.tf            # Output values and useful commands
├── terraform.tfvars      # Configuration values (customize for your needs)
├── lambda_function.py    # Python code for the Lambda function
└── README.md             # This file
```

## 🚀 Quick Start

### Prerequisites

1. **AWS CLI configured** with appropriate permissions
2. **Terraform** installed (>= 1.0)
3. **AWS Config enabled** in your region (see setup instructions below)

### 1. Enable AWS Config (if not already enabled)

```bash
# Check if Config is enabled
aws configservice describe-configuration-recorders

# If no recorders exist, run this setup script:
BUCKET="aws-config-$(aws sts get-caller-identity --query Account --output text)-$(aws configure get region)"
aws s3 mb s3://$BUCKET

aws iam create-service-linked-role --aws-service-name config.amazonaws.com || true

aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig \
  --recording-group allSupported=true,includeGlobalResourceTypes=true

aws configservice put-delivery-channel \
  --delivery-channel name=default,s3BucketName=$BUCKET

aws configservice start-configuration-recorder --configuration-recorder-name=default
```

### 2. Clone and Deploy

```bash
# Clone this repository
git clone <repository-url>
cd s3-classification-config

# Customize configuration (optional)
nano terraform.tfvars

# Initialize and deploy
terraform init
terraform plan
terraform apply
```

### 3. Test the Rule

```bash
# Create a test bucket (non-compliant)
TEST_BUCKET="test-bucket-$(date +%s)"
aws s3 mb s3://$TEST_BUCKET

# Trigger Config rule evaluation
aws configservice start-config-rules-evaluation --config-rule-names $(terraform output -raw config_rule_name)

# Wait 2-3 minutes, then check results
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name $(terraform output -raw config_rule_name) \
  --query 'EvaluationResults[*].{Bucket:EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,Status:ComplianceType,Issues:Annotation}' \
  --output table
```

### 4. Make a Bucket Compliant

```bash
# Add required tags to make it compliant
aws s3api put-bucket-tagging --bucket $TEST_BUCKET --tagging 'TagSet=[
  {Key=DataClassification,Value=internal},
  {Key=Owner,Value=test-team}
]'

# Trigger evaluation again
aws configservice start-config-rules-evaluation --config-rule-names $(terraform output -raw config_rule_name)

# Check results (should now show COMPLIANT)
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name $(terraform output -raw config_rule_name) \
  --query 'EvaluationResults[?EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId==`'$TEST_BUCKET'`]'
```

## ⚙️ Customization

Edit `terraform.tfvars` to customize the rule for your organization:

### Basic Configuration
```hcl
# Project settings
project_name = "my-s3-compliance-rule"
aws_region   = "us-west-2"

# Email for notifications
notification_email = "security-team@company.com"
```

### Compliance Rules
```hcl
# Required tags
required_tags = [
  "DataClassification",
  "Owner",
  "Environment",
  "CostCenter"
]

# Valid data classification levels
valid_classifications = [
  "public",
  "internal", 
  "confidential",
  "restricted"
]

# Bucket naming pattern (regex)
naming_pattern = "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
```

### Industry-Specific Examples

**Financial Services:**
```hcl
valid_classifications = ["public", "internal", "confidential", "restricted", "pci-dss"]
required_tags = ["DataClassification", "Owner", "Regulation", "RetentionPeriod"]
naming_pattern = "^(pci|sox|pii)-[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
```

**Healthcare (HIPAA):**
```hcl
valid_classifications = ["public", "internal", "phi", "restricted"]
required_tags = ["DataClassification", "Owner", "PHI", "Purpose"]
naming_pattern = "^(phi|hipaa|secure)-[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
```

## 📊 Monitoring

### View Lambda Logs
```bash
# Real-time logs
aws logs tail "/aws/lambda/$(terraform output -raw lambda_function_name)" --follow

# Recent errors
aws logs filter-log-events \
  --log-group-name "/aws/lambda/$(terraform output -raw lambda_function_name)" \
  --filter-pattern "ERROR" \
  --start-time $(date -d '1 hour ago' +%s)000
```

### Check Config Rule Status
```bash
# Rule evaluation status
aws configservice describe-config-rule-evaluation-status \
  --config-rule-names $(terraform output -raw config_rule_name)

# Compliance summary
aws configservice get-compliance-summary
```

### Email Notifications
If you set `notification_email` in `terraform.tfvars`, you'll receive email alerts when:
- Lambda function errors occur
- You'll need to confirm the SNS subscription in your email

## 🧪 Testing Commands

The deployment outputs useful testing commands:

```bash
# Get all available testing commands
terraform output test_commands

# Example output:
# {
#   "check_compliance" = "aws configservice get-compliance-details-by-config-rule --config-rule-name s3-classification-config-rule"
#   "trigger_evaluation" = "aws configservice start-config-rules-evaluation --config-rule-names s3-classification-config-rule"  
#   "view_logs" = "aws logs tail /aws/lambda/s3-classification-config-lambda --follow"
# }
```

## 🔧 Troubleshooting

### Common Issues

**1. Config Rule Not Finding Resources**
```bash
# Check if Config is recording S3 buckets
aws configservice list-discovered-resources --resource-type AWS::S3::Bucket --limit 5

# Verify Config recorder is active
aws configservice describe-configuration-recorder-status --configuration-recorder-names default
```

**2. Lambda Permission Errors**
```bash
# Check Lambda execution role permissions
aws iam get-role-policy \
  --role-name $(terraform output -raw lambda_function_name | sed 's/lambda/lambda-role/') \
  --policy-name $(terraform output -raw lambda_function_name | sed 's/lambda/lambda-policy/')
```

**3. No Compliance Results**
```bash
# Check if Lambda is being invoked
aws logs filter-log-events \
  --log-group-name "/aws/lambda/$(terraform output -raw lambda_function_name)" \
  --filter-pattern "Received event" \
  --start-time $(date -d '10 minutes ago' +%s)000

# Force evaluation
aws configservice start-config-rules-evaluation --config-rule-names $(terraform output -raw config_rule_name)
```

**4. Config Rule Shows No Source Details**
```bash
# Recreate the Config rule
terraform destroy -target=aws_config_config_rule.s3_classification_rule
terraform apply
```

### Debug Mode

For detailed debugging, check Lambda logs after triggering an evaluation:
```bash
aws configservice start-config-rules-evaluation --config-rule-names $(terraform output -raw config_rule_name)
sleep 60
aws logs tail "/aws/lambda/$(terraform output -raw lambda_function_name)" --since 5m
```

## 📈 Advanced Usage

### Integration with Other Tools

**1. Automated Remediation**: Extend the Lambda function to automatically fix compliance issues
**2. Custom Dashboards**: Use CloudWatch dashboards to visualize compliance trends  
**3. CI/CD Integration**: Include compliance checks in your deployment pipelines
**4. Multi-Account**: Deploy across multiple AWS accounts using AWS Organizations

### Extending the Rule

To add new compliance checks, modify the `evaluate_bucket()` function in `lambda_function.py`:

```python
# Example: Check bucket versioning
try:
    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
    if versioning.get('Status') != 'Enabled':
        issues.append("Bucket versioning must be enabled")
except Exception as e:
    print(f"Error checking versioning: {e}")
```

## 🧹 Cleanup

```bash
# Remove test resources
aws s3 rb s3://$TEST_BUCKET --force

# Destroy all Terraform resources
terraform destroy

# Optionally disable Config (will stop all Config rules)
aws configservice stop-configuration-recorder --configuration-recorder-name default
aws configservice delete-configuration-recorder --configuration-recorder-name default
aws configservice delete-delivery-channel --delivery-channel-name default
```

## 📚 What You'll Learn

This project teaches:

- ✅ **AWS Config Custom Rules**: How to create rules that enforce organizational policies
- ✅ **Lambda Integration**: Building serverless compliance checking functions  
- ✅ **Infrastructure as Code**: Using Terraform for AWS deployments
- ✅ **S3 Security**: Understanding S3 tagging, encryption, and access controls
- ✅ **Compliance Automation**: Automatically monitoring and reporting policy violations

## 🤝 Contributing

Feel free to submit issues and enhancement requests! This is a learning project designed to demonstrate AWS Config custom rule concepts.

## 📄 License

This project is intended for educational and demonstration purposes.

---

## 🎉 Success!

If you see your S3 buckets showing up as COMPLIANT or NON_COMPLIANT in the Config console, you've successfully:

1. ✅ Created a custom AWS Config rule
2. ✅ Deployed it with Terraform
3. ✅ Integrated it with AWS Lambda  
4. ✅ Learned about AWS compliance automation

Your custom rule is now continuously monitoring your S3 buckets and enforcing your organization's data classification policies! 🚀