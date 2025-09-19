import json
import re
from datetime import datetime

import boto3

# Initialize AWS clients
config_client = boto3.client("config")
s3_client = boto3.client("s3")

def lambda_handler(event, context):
    """AWS Config custom rule for S3 bucket compliance."""
    print(f"Received event: {json.dumps(event, indent=2, default=str)}")

    # Handle scheduled notifications (evaluate all S3 buckets)
    if event.get("eventLeftScope") == False and "configurationItem" not in event:
        print("Handling scheduled notification - evaluating all S3 buckets")
        return handle_scheduled_notification(event)

    # Handle configuration item changes
    configuration_item = event.get("configurationItem", {})
    if not configuration_item:
        return {"statusCode": 200, "body": "No configuration item"}

    # Only evaluate S3 buckets
    if configuration_item.get("resourceType") != "AWS::S3::Bucket":
        return {"statusCode": 200, "body": "Not an S3 bucket"}

    bucket_name = configuration_item.get("resourceName")
    if not bucket_name:
        return {"statusCode": 400, "body": "No bucket name"}

    # Get rule parameters
    rule_parameters = json.loads(event.get("ruleParameters", "{}"))

    print(f"Evaluating single bucket: {bucket_name}")

    # Evaluate compliance
    compliance_result = evaluate_bucket(bucket_name, rule_parameters)

    # Submit result to Config
    submit_evaluation(event, configuration_item, compliance_result)

    return {"statusCode": 200, "body": f"Evaluated {bucket_name}"}

def handle_scheduled_notification(event):
    """Handle scheduled notifications by evaluating all S3 buckets."""
    try:
        # Get rule parameters
        rule_parameters = json.loads(event.get("ruleParameters", "{}"))

        # List all S3 buckets
        print("📋 Listing all S3 buckets...")
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])

        print(f"Found {len(buckets)} S3 buckets to evaluate")

        evaluations = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            print(f"Evaluating scheduled bucket: {bucket_name}")

            # Evaluate compliance
            compliance_result = evaluate_bucket(bucket_name, rule_parameters)

            # Create evaluation result
            evaluation = {
                "ComplianceResourceType": "AWS::S3::Bucket",
                "ComplianceResourceId": bucket_name,
                "ComplianceType": compliance_result["compliance"],
                "Annotation": compliance_result["annotation"],
                "OrderingTimestamp": datetime.utcnow(),
            }
            evaluations.append(evaluation)
            print(f"  Result: {compliance_result['compliance']} - {compliance_result['annotation']}")

        # Submit all evaluations to Config
        result_token = event.get("resultToken", str(datetime.utcnow()))
        print(f"📤 Submitting {len(evaluations)} evaluations to Config")

        # Submit in batches of 100
        for i in range(0, len(evaluations), 100):
            batch = evaluations[i:i+100]
            try:
                response = config_client.put_evaluations(
                    Evaluations=batch,
                    ResultToken=result_token,
                )
                print(f"✅ Successfully submitted batch of {len(batch)} evaluations")

                # Check for failures
                failed_evaluations = response.get("FailedEvaluations", [])
                if failed_evaluations:
                    print(f"❌ Failed evaluations in batch: {failed_evaluations}")

            except Exception as e:
                print(f"❌ Error submitting batch: {e}")
                raise e

        return {"statusCode": 200, "body": f"Evaluated {len(buckets)} buckets"}

    except Exception as e:
        print(f"💥 Error in scheduled evaluation: {e}")
        return {"statusCode": 500, "body": f"Error: {e!s}"}

def evaluate_bucket(bucket_name, rule_parameters):
    """Evaluate bucket compliance."""
    required_tags = rule_parameters.get("requiredTags", ["DataClassification", "Owner"])
    valid_classifications = rule_parameters.get("validClassifications", ["public", "internal", "confidential", "restricted"])
    naming_pattern = rule_parameters.get("namingPattern", r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

    issues = []

    try:
        # Check if bucket exists
        try:
            s3_client.head_bucket(Bucket=bucket_name)
        except s3_client.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ["404", "NoSuchBucket"]:
                return {"compliance": "NOT_APPLICABLE", "annotation": "Bucket no longer exists"}

        # Check naming pattern
        if not re.match(naming_pattern, bucket_name):
            issues.append("Invalid bucket name format")

        # Get bucket tags
        try:
            response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            bucket_tags = {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}
            print(f"  Bucket {bucket_name} tags: {list(bucket_tags.keys()) if bucket_tags else 'None'}")
        except s3_client.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                bucket_tags = {}
                print(f"  Bucket {bucket_name} has no tags")
            else:
                raise e

        # Check required tags
        missing_tags = [tag for tag in required_tags if tag not in bucket_tags]
        if missing_tags:
            issues.append(f"Missing required tags: {', '.join(missing_tags)}")

        # Check data classification
        data_classification = bucket_tags.get("DataClassification", "").lower()
        if data_classification and data_classification not in [cls.lower() for cls in valid_classifications]:
            issues.append(f"Invalid DataClassification: {data_classification}")

        # Check security for sensitive data
        if data_classification in ["confidential", "restricted"]:
            # Check encryption
            try:
                s3_client.get_bucket_encryption(Bucket=bucket_name)
            except s3_client.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    issues.append("Sensitive data bucket must have encryption")

            # Check public access block
            try:
                response = s3_client.get_public_access_block(Bucket=bucket_name)
                pab = response.get("PublicAccessBlockConfiguration", {})
                required_settings = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
                if not all([pab.get(setting, False) for setting in required_settings]):
                    issues.append("Sensitive data bucket must block public access")
            except s3_client.exceptions.ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    issues.append("Sensitive data bucket must have public access block configured")

    except Exception as e:
        print(f"Error evaluating bucket {bucket_name}: {e}")
        issues.append(f"Error evaluating bucket: {e!s}")

    # Return result
    if issues:
        print(f"  {bucket_name} is NON_COMPLIANT: {'; '.join(issues)}")
        return {"compliance": "NON_COMPLIANT", "annotation": "; ".join(issues)}
    print(f"  {bucket_name} is COMPLIANT")
    return {"compliance": "COMPLIANT", "annotation": "Bucket meets all requirements"}

def submit_evaluation(event, configuration_item, compliance_result):
    """Submit evaluation result to AWS Config."""
    evaluation = {
        "ComplianceResourceType": configuration_item.get("resourceType"),
        "ComplianceResourceId": configuration_item.get("resourceId"),
        "ComplianceType": compliance_result["compliance"],
        "Annotation": compliance_result["annotation"],
        "OrderingTimestamp": datetime.utcnow(),
    }

    result_token = event.get("resultToken", str(datetime.utcnow()))

    print(f"Submitting evaluation for {configuration_item.get('resourceName')}: {compliance_result['compliance']}")

    try:
        response = config_client.put_evaluations(
            Evaluations=[evaluation],
            ResultToken=result_token,
        )
        print("✅ Successfully submitted evaluation")

        # Check for failures
        failed_evaluations = response.get("FailedEvaluations", [])
        if failed_evaluations:
            print(f"❌ Failed evaluations: {failed_evaluations}")

    except Exception as e:
        print(f"❌ Error submitting evaluation: {e}")
        raise
