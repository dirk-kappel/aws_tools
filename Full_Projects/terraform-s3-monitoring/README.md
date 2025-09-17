# AWS S3 Monitoring with CloudTrail, CloudWatch Logs, and Lambda

This Terraform project creates a complete S3 monitoring solution that:
- Uses CloudTrail to track ALL S3 API calls (GET, PUT, DELETE, HEAD, etc.)
- Sends CloudTrail logs to CloudWatch Logs for real-time processing
- Triggers a Lambda function via CloudWatch Logs subscription filter
- Captures detailed user information (username, IP address, user agent)
- Stores structured logs in CloudWatch for analysis

## Architecture

- **S3 Bucket** (primary) - The monitored bucket with versioning enabled
- **S3 Bucket** (CloudTrail logs) - Stores CloudTrail log files as backup
- **CloudTrail Trail** - Tracks S3 API calls with data events
- **CloudWatch Log Group** (CloudTrail) - Receives CloudTrail logs in real-time
- **CloudWatch Logs Subscription Filter** - Filters S3 events and triggers Lambda
- **Lambda Function** - Processes CloudTrail events and creates structured logs
- **CloudWatch Log Group** (Lambda) - Stores Lambda execution logs

## Deployment

### 1. Initialize and Deploy

```bash
# Navigate to your project directory
cd terraform-s3-monitoring

# Initialize Terraform
terraform init

# Review the deployment plan
terraform plan

# Deploy the infrastructure
terraform apply
```

When prompted, type `yes` to confirm the deployment.

### 2. Expected Output

After successful deployment, you should see output similar to:

```
Apply complete! Resources: 15 added, 0 changed, 0 destroyed.

Outputs:
primary_bucket_name = "my-monitored-bucket-abc12345"
lambda_function_name = "s3-event-processor"
cloudwatch_log_group_name = "/aws/lambda/s3-event-processor"
test_commands = {
  "upload_test_file" = "aws s3 cp test.txt s3://my-monitored-bucket-abc12345/"
  "view_lambda_logs" = "aws logs tail /aws/lambda/s3-event-processor --follow"
  "view_cloudtrail_logs" = "aws s3 ls s3://cloudtrail-logs-bucket-abc12345/cloudtrail-logs/ --recursive"
}
```

## Testing the Setup

### Test 1: Upload a File (PutObject)

```bash
# Create a test file
echo "Hello, S3 monitoring!" > test.txt

# Get bucket name from Terraform output
BUCKET_NAME=$(terraform output -raw primary_bucket_name)

# Upload to monitored bucket
aws s3 cp test.txt s3://$BUCKET_NAME/

# Expected output:
# upload: ./test.txt to s3://my-monitored-bucket-abc12345/test.txt
```

### Test 2: Download a File (GetObject)

```bash
# Download file (triggers GetObject event)
aws s3 cp s3://$BUCKET_NAME/test.txt downloaded-test.txt

# Expected output:
# download: s3://my-monitored-bucket-abc12345/test.txt to ./downloaded-test.txt
```

### Test 3: Check File Metadata (HeadObject)

```bash
# Check file info (triggers HeadObject event)
aws s3api head-object --bucket $BUCKET_NAME --key test.txt

# Or list files with details (also triggers HeadObject)
aws s3 ls s3://$BUCKET_NAME/ --human-readable --summarize
```

### Test 4: Monitor Lambda Logs (Real-time)

```bash
# Watch Lambda logs as events are processed
LOG_GROUP=$(terraform output -raw lambda_log_group_name)
aws logs tail $LOG_GROUP --follow

# You should see CloudTrail events like:
# S3 EventBridge Raw Event:
# {
#   "awslogs": {
#     "data": "H4sI...base64encoded..."
#   }
# }
```

### Test 5: Perform Multiple Operations

```bash
BUCKET_NAME=$(terraform output -raw primary_bucket_name)

# Upload multiple files (PutObject events)
echo "Document content" > document.pdf
echo "Image data" > photo.jpg
aws s3 cp document.pdf s3://$BUCKET_NAME/documents/
aws s3 cp photo.jpg s3://$BUCKET_NAME/images/

# Check file existence (HeadObject events)
aws s3api head-object --bucket $BUCKET_NAME --key document.pdf

# Download files (GetObject events)  
aws s3 cp s3://$BUCKET_NAME/documents/document.pdf ./downloaded-doc.pdf

# Delete files (DeleteObject events)
aws s3 rm s3://$BUCKET_NAME/documents/document.pdf

# List all objects (may trigger additional HeadObject events)
aws s3 ls s3://$BUCKET_NAME/ --recursive
```

### Test 6: Verify CloudTrail Logs in S3

```bash
# Check CloudTrail logs backup (may take 5-15 minutes to appear)
CLOUDTRAIL_BUCKET=$(terraform output -raw cloudtrail_logs_bucket_name)
aws s3 ls s3://$CLOUDTRAIL_BUCKET/cloudtrail-logs/ --recursive

# Download and inspect a log file
aws s3 cp s3://$CLOUDTRAIL_BUCKET/cloudtrail-logs/[LOG_FILE_NAME].json.gz ./
gunzip [LOG_FILE_NAME].json.gz
cat [LOG_FILE_NAME].json | jq '.'
```

## Expected Lambda Log Output

When functioning correctly, your Lambda logs will contain CloudTrail events with rich user information:

### Raw CloudTrail Event Structure:
```json
{
  "awslogs": {
    "data": "H4sIAA...compressed_and_encoded_data..."
  }
}
```

### Decoded CloudTrail S3 Event:
```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDA2SAECBDNPHDMZERDA",
    "arn": "arn:aws:iam::123456789012:user/john.doe",
    "accountId": "123456789012",
    "accessKeyId": "AKIA2SAECBDNEX55FHX6",
    "userName": "john.doe"
  },
  "eventTime": "2025-09-16T16:11:50Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "GetObject",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "192.168.1.100",
  "userAgent": "[aws-cli/2.22.18...]",
  "requestParameters": {
    "bucketName": "my-monitored-bucket-abc12345",
    "key": "test.txt"
  },
  "resources": [
    {
      "type": "AWS::S3::Object",
      "ARN": "arn:aws:s3:::my-monitored-bucket-abc12345/test.txt"
    }
  ],
  "eventType": "AwsApiCall",
  "eventCategory": "Data",
  "readOnly": true
}
```

### Captured Operations:
- **PutObject** - File uploads
- **GetObject** - File downloads  
- **DeleteObject** - File deletions
- **HeadObject** - Metadata requests (file existence checks, AWS Console browsing)
- **CopyObject** - File copies
- **RestoreObject** - Glacier restores

## Monitoring and Verification

### View Logs in AWS Console

1. **Lambda Logs**: Navigate to **AWS CloudWatch Console** → **Log Groups** → `/aws/lambda/s3-event-processor`
2. **CloudTrail Logs**: Navigate to **AWS CloudWatch Console** → **Log Groups** → `cloudtrail-s3-api-logs`
3. Click on the most recent log stream to see events

### Check CloudTrail Status

```bash
# Verify CloudTrail is active and configured correctly
aws cloudtrail get-trail-status --name s3-monitoring-trail

# Check CloudTrail configuration
aws cloudtrail describe-trails --trail-name-list s3-monitoring-trail
```

### Check CloudWatch Logs Subscription Filter

```bash
# Verify subscription filter is active
aws logs describe-subscription-filters --log-group-name cloudtrail-s3-api-logs

# Check if Lambda is getting invoked
aws lambda get-function --function-name s3-event-processor
```

### CloudWatch Logs Filter Pattern

The subscription filter uses this pattern to capture S3 events:
```json
{$.eventName=PutObject || $.eventName=GetObject || $.eventName=DeleteObject || $.eventName=HeadObject}
```

### Lambda Function Metrics

```bash
# View Lambda invocation metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=s3-event-processor \
  --statistics Sum \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300

# Check for Lambda errors
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Errors \
  --dimensions Name=FunctionName,Value=s3-event-processor \
  --statistics Sum \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300
```

## Troubleshooting

### No Lambda Logs Appearing

```bash
# Check if CloudTrail is sending logs to CloudWatch
aws logs describe-log-streams --log-group-name cloudtrail-s3-api-logs

# Check if CloudTrail is active
aws cloudtrail get-trail-status --name s3-monitoring-trail

# Verify subscription filter exists and is properly configured
aws logs describe-subscription-filters --log-group-name cloudtrail-s3-api-logs
```

### CloudTrail Not Logging to CloudWatch

```bash
# Check CloudTrail configuration
aws cloudtrail describe-trails --trail-name-list s3-monitoring-trail \
  --query 'trailList[0].{CloudWatchLogsLogGroupArn:CloudWatchLogsLogGroupArn,CloudWatchLogsRoleArn:CloudWatchLogsRoleArn}'

# Check CloudWatch Logs IAM role permissions
aws iam get-role --role-name cloudtrail-cloudwatch-logs-role

# List attached policies
aws iam list-role-policies --role-name cloudtrail-cloudwatch-logs-role
```

### Lambda Permission Issues

```bash
# Check Lambda execution role
aws iam get-role --role-name s3-event-processor-lambda-role

# Verify CloudWatch Logs can invoke Lambda
aws lambda get-policy --function-name s3-event-processor
```

### Subscription Filter Not Triggering Lambda

```bash
# Test subscription filter manually
aws logs put-log-events \
  --log-group-name cloudtrail-s3-api-logs \
  --log-stream-name test-stream \
  --log-events timestamp=$(date +%s000),message='{"eventSource":"s3.amazonaws.com","eventName":"PutObject","eventCategory":"Data"}'

# Check recent Lambda invocations
aws lambda list-invocations --function-name s3-event-processor
```

## Cost Estimation

For a sandbox environment with moderate testing:

- **S3 Storage**: ~$0.01-0.05/month
- **Lambda Execution**: Usually covered by free tier
- **CloudTrail Data Events**: ~$0.10/100k events
- **EventBridge Custom Events**: ~$1.00/million events  
- **CloudWatch Logs**: ~$0.50/GB ingested
- **Total estimated cost**: ~$1-5/month for testing

## Resource Cleanup

⚠️ **Important**: Follow these steps in order to avoid cleanup issues.

### Step 1: Stop CloudTrail to Prevent New Logs

```bash
# Stop CloudTrail first to prevent new logs from being created
aws cloudtrail stop-logging --name s3-monitoring-trail

# Verify CloudTrail is stopped
aws cloudtrail get-trail-status --name s3-monitoring-trail
```

### Step 2: Empty S3 Buckets (Including Versioned Objects)

#### Empty Primary Bucket (handles versioning):
```bash
# Get primary bucket name
PRIMARY_BUCKET=$(terraform output -raw primary_bucket_name)

# Delete all object versions and delete markers
aws s3api list-object-versions --bucket $PRIMARY_BUCKET --query 'Versions[].{Key:Key,VersionId:VersionId}' --output text | while read key versionId; do
  if [ ! -z "$key" ] && [ ! -z "$versionId" ]; then
    echo "Deleting version $versionId of $key"
    aws s3api delete-object --bucket $PRIMARY_BUCKET --key "$key" --version-id "$versionId"
  fi
done

# Delete all delete markers
aws s3api list-object-versions --bucket $PRIMARY_BUCKET --query 'DeleteMarkers[].{Key:Key,VersionId:VersionId}' --output text | while read key versionId; do
  if [ ! -z "$key" ] && [ ! -z "$versionId" ]; then
    echo "Deleting delete marker $versionId of $key"
    aws s3api delete-object --bucket $PRIMARY_BUCKET --key "$key" --version-id "$versionId"
  fi
done

# Remove any remaining objects (cleanup)
aws s3 rm s3://$PRIMARY_BUCKET --recursive

# Verify bucket is empty
aws s3 ls s3://$PRIMARY_BUCKET --recursive
```

#### Empty CloudTrail Logs Bucket:
```bash
# Get CloudTrail bucket name  
CLOUDTRAIL_BUCKET=$(terraform output -raw cloudtrail_logs_bucket_name)

# Empty the CloudTrail logs bucket
aws s3 rm s3://$CLOUDTRAIL_BUCKET --recursive

# Verify bucket is empty
aws s3 ls s3://$CLOUDTRAIL_BUCKET --recursive
```

### Step 3: Delete CloudWatch Logs Subscription Filter

```bash
# Remove subscription filter to prevent Lambda invocations during cleanup
aws logs delete-subscription-filter \
  --log-group-name cloudtrail-s3-api-logs \
  --filter-name s3-api-events-filter
```

### Step 4: Destroy Infrastructure

```bash
# Now safely destroy all Terraform-managed resources
terraform destroy

# When prompted, type 'yes' to confirm
```

### Step 5: Clean Up Local Files

```bash
# Remove generated files
rm -f test.txt document.pdf photo.jpg downloaded-*.txt downloaded-*.pdf
rm -f s3_event_processor.zip
rm -f *.json.gz *.json

# Optional: Remove Terraform state files (if not needed for future deployments)
rm -f terraform.tfstate terraform.tfstate.backup
rm -rf .terraform/
```

### Alternative: Automated Cleanup Script

Create a cleanup script `cleanup.sh`:

```bash
#!/bin/bash
set -e

echo "Starting cleanup process..."

# Get bucket names
PRIMARY_BUCKET=$(terraform output -raw primary_bucket_name 2>/dev/null || echo "")
CLOUDTRAIL_BUCKET=$(terraform output -raw cloudtrail_logs_bucket_name 2>/dev/null || echo "")

# Stop CloudTrail
echo "Stopping CloudTrail..."
aws cloudtrail stop-logging --name s3-monitoring-trail 2>/dev/null || true

# Empty primary bucket with versioning
if [ ! -z "$PRIMARY_BUCKET" ]; then
    echo "Emptying primary bucket: $PRIMARY_BUCKET"
    
    # Delete versions
    aws s3api list-object-versions --bucket $PRIMARY_BUCKET --output text --query 'Versions[].{Key:Key,VersionId:VersionId}' | while read key versionId; do
        if [ ! -z "$key" ] && [ "$key" != "None" ] && [ ! -z "$versionId" ] && [ "$versionId" != "None" ]; then
            echo "Deleting $key version $versionId"
            aws s3api delete-object --bucket $PRIMARY_BUCKET --key "$key" --version-id "$versionId"
        fi
    done
    
    # Delete delete markers
    aws s3api list-object-versions --bucket $PRIMARY_BUCKET --output text --query 'DeleteMarkers[].{Key:Key,VersionId:VersionId}' | while read key versionId; do
        if [ ! -z "$key" ] && [ "$key" != "None" ] && [ ! -z "$versionId" ] && [ "$versionId" != "None" ]; then
            echo "Deleting delete marker $key version $versionId"
            aws s3api delete-object --bucket $PRIMARY_BUCKET --key "$key" --version-id "$versionId"
        fi
    done
    
    # Final cleanup
    aws s3 rm s3://$PRIMARY_BUCKET --recursive 2>/dev/null || true
fi

# Empty CloudTrail bucket
if [ ! -z "$CLOUDTRAIL_BUCKET" ]; then
    echo "Emptying CloudTrail bucket: $CLOUDTRAIL_BUCKET"
    aws s3 rm s3://$CLOUDTRAIL_BUCKET --recursive 2>/dev/null || true
fi

# Remove subscription filter
echo "Removing subscription filter..."
aws logs delete-subscription-filter --log-group-name cloudtrail-s3-api-logs --filter-name s3-api-events-filter 2>/dev/null || true

echo "Ready for terraform destroy"
echo "Run: terraform destroy"
```

Make it executable and run:
```bash
chmod +x cleanup.sh
./cleanup.sh
terraform destroy
```

### Verification

After cleanup, verify all resources are deleted:

```bash
# Check if CloudTrail trail is deleted (should return error)
aws cloudtrail get-trail-status --name s3-monitoring-trail 2>/dev/null || echo "CloudTrail deleted successfully"

# Check if S3 buckets are deleted (should return empty or error)
aws s3 ls | grep -E "(monitored-bucket|cloudtrail-logs-bucket)" || echo "S3 buckets deleted successfully"

# Check if Lambda function is deleted (should return error)
aws lambda get-function --function-name s3-event-processor 2>/dev/null || echo "Lambda function deleted successfully"

# Check if CloudWatch Log Groups are deleted (should return empty)
aws logs describe-log-groups --log-group-name-prefix "cloudtrail-s3-api-logs"
aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/s3-event-processor"
```

## Additional Notes

- **Event Latency**: CloudTrail events typically arrive in CloudWatch Logs within 1-5 minutes, faster than S3-stored logs (5-15 minutes)
- **Lambda Timeout**: Set to 30 seconds, sufficient for processing CloudTrail log events
- **Log Retention**: CloudWatch logs retained for 14 days by default to control costs
- **Security**: All S3 buckets have public access blocked by default
- **Comprehensive Coverage**: Captures ALL S3 operations (GET, PUT, DELETE, HEAD, COPY, etc.) with detailed user context
- **User Information**: Unlike EventBridge, CloudTrail provides rich user identity, IP addresses, and user agents

## Cost Optimization

For sandbox environments:
- CloudWatch Logs: ~$0.50/GB ingested
- Lambda Execution: Usually covered by free tier
- CloudTrail Data Events: ~$0.10/100k events
- S3 Storage: Minimal for log files
- **Total estimated cost**: ~$2-10/month depending on S3 activity volume

## Support

If you encounter issues:

1. Check CloudTrail status: `aws cloudtrail get-trail-status --name s3-monitoring-trail`
2. Verify CloudWatch Logs: `aws logs describe-log-streams --log-group-name cloudtrail-s3-api-logs`
3. Check Lambda logs for processing errors: `aws logs tail /aws/lambda/s3-event-processor`
4. Review subscription filter configuration: `aws logs describe-subscription-filters --log-group-name cloudtrail-s3-api-logs`