# 🚀 DynamoDB Streaming & SNS Notification System - Deployment Guide

## Project Overview

This project creates a real-time message notification system that demonstrates:
- **DynamoDB Streams** for capturing data changes
- **Lambda Functions** for event processing
- **SNS** for notifications
- **Event-driven architecture** patterns

## 📁 File Structure

```
your-project/
├── main.tf                    # Main Terraform configuration
├── variables.tf               # Variable definitions  
├── terraform.tfvars          # Variable values (update with your info)
├── lambda_function.py         # Lambda function source code
├── insert_messages.py         # Script to insert test messages
├── sns_test_script.py         # SNS topic testing script
├── end_to_end_test.py         # Complete pipeline test
└── outputs.tf                 # Output values
```

## 🛠️ Prerequisites

1. **AWS CLI configured** with appropriate credentials
2. **Terraform installed** (version 1.0+)
3. **Python 3.8+** with boto3 installed:
   ```bash
   pip install boto3
   ```

## 📋 Step-by-Step Deployment

### Step 1: Update Configuration Files

1. **Edit `terraform.tfvars`**:
   ```hcl
   notification_email = "your-actual-email@example.com"
   aws_region = "us-east-1"  # or your preferred region
   environment = "learning"
   project_name = "dynamodb-streaming-triggers"
   ```

2. **Create `lambda_function.py`** from the Lambda Function Code artifact

3. **Create main Terraform files** with the configurations from all artifacts

### Step 2: Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Review the deployment plan
terraform plan

# Apply the configuration
terraform apply
```

**Expected resources created:**
- ✅ DynamoDB table with streams enabled
- ✅ SNS topic and subscriptions
- ✅ SQS queue for testing
- ✅ Lambda function with proper IAM roles
- ✅ Event source mapping
- ✅ CloudWatch log group

### Step 3: Confirm Email Subscription

1. **Check your email** for SNS subscription confirmation
2. **Click the confirmation link** to activate email notifications

### Step 4: Test the System

#### Test 1: Manual Message Insertion
```bash
# Run the message insertion script
python insert_messages.py
```
- Should insert sample messages
- Check email for notifications
- Verify in AWS Console that stream records are generated

#### Test 2: SNS Topic Test
```bash
# Update SNS_TOPIC_ARN and SQS_QUEUE_URL in the script first
terraform output sns_topic_arn
terraform output sqs_queue_url

# Run SNS test
python sns_test_script.py
```

#### Test 3: End-to-End Pipeline Test
```bash
# Update SQS_QUEUE_URL in end_to_end_test.py
terraform output sqs_queue_url

# Run complete pipeline test
python end_to_end_test.py
```

## 🔍 Verification Checklist

### ✅ DynamoDB
- [ ] Table `messages` exists
- [ ] Streams enabled with `NEW_AND_OLD_IMAGES`
- [ ] GSI indexes created (`timestamp-index`, `author-index`)
- [ ] Test messages inserted successfully

### ✅ Lambda Function
- [ ] Function `message-stream-processor` deployed
- [ ] Event source mapping active
- [ ] CloudWatch logs show successful executions
- [ ] No errors in `/aws/lambda/message-stream-processor` logs

### ✅ SNS & Notifications
- [ ] Topic `message-notifications` exists
- [ ] Email subscription confirmed and active
- [ ] SQS subscription receiving messages
- [ ] Email notifications arrive in inbox

### ✅ Complete Pipeline
- [ ] New messages trigger notifications
- [ ] Reply messages include original message context
- [ ] Lambda processes stream events correctly
- [ ] No messages stuck in dead letter queues

## 📊 Monitoring & Troubleshooting

### CloudWatch Logs
```bash
# View Lambda logs
aws logs tail /aws/lambda/message-stream-processor --follow
```

### DynamoDB Stream Monitoring
- Check **DynamoDB Console → Table → Exports and streams**
- Verify stream records are being generated

### Lambda Function Metrics
- **CloudWatch → Lambda → Functions → message-stream-processor**
- Monitor: Invocations, Errors, Duration, Throttles

### Common Issues & Solutions

**Issue**: Lambda not triggering
- ✅ Check event source mapping is active
- ✅ Verify stream ARN is correct
- ✅ Check Lambda execution role permissions

**Issue**: SNS notifications not received
- ✅ Confirm email subscription
- ✅ Check spam folder
- ✅ Verify SNS publish permissions
- ✅ Test with SQS subscription first

**Issue**: Reply notifications missing original message
- ✅ Check DynamoDB read permissions
- ✅ Verify `reply_to_message_id` field is set correctly
- ✅ Look for errors in Lambda logs

## 🧪 Testing Scenarios

### Scenario 1: Basic Message Flow
```python
# Insert a new message
message = insert_message("alice", "Hello world!")
# Expected: Email notification received within 10 seconds
```

### Scenario 2: Reply Chain
```python
# Insert original message
original = insert_message("bob", "What's for lunch?")

# Insert reply
reply = insert_message("charlie", "Pizza!", original['message_id'])
# Expected: Email with both original and reply content
```

### Scenario 3: High Volume Test
```python
# Insert multiple messages rapidly
for i in range(10):
    insert_message(f"user_{i}", f"Message {i}")
# Expected: All notifications received, Lambda handles batching
```

## 🔄 Next Steps & Enhancements

Once the basic system is working, consider these enhancements:

1. **Add message filtering** - Only notify for certain authors or keywords
2. **Implement notification preferences** - Let users choose notification types
3. **Add message threading** - Visual reply chains in notifications
4. **Create a web interface** - React app to send/view messages
5. **Add analytics** - Track popular authors, message frequency
6. **Implement message search** - ElasticSearch integration

## 🧹 Cleanup

To remove all resources and avoid charges:
```bash
terraform destroy
```

This will remove all AWS resources created by this project.

## 📚 Key Learning Points

This project demonstrates:
- **Event-driven architecture** with real-time processing
- **DynamoDB Streams** for change data capture
- **Lambda function** stream processing patterns
- **SNS fan-out** notification patterns
- **IAM roles and policies** for service integration
- **Infrastructure as Code** with Terraform
- **Error handling** with dead letter queues
- **Monitoring** with CloudWatch

## 🆘 Support

If you encounter issues:
1. Check CloudWatch logs for detailed error messages
2. Verify all IAM permissions are correct
3. Ensure all ARNs and resource names match terraform outputs
4. Test individual components (DynamoDB → Lambda → SNS) separately