#!/usr/bin/env python3
"""
AWS S3 Bucket Configuration Auditor.

A comprehensive inventory tool that scans all S3 buckets in an AWS account
and extracts detailed configuration information for security and compliance
auditing purposes.

Prerequisites:
- AWS credentials configured with appropriate permissions
- Boto3 library installed (pip install boto3)
- Required S3 permissions:
  * s3:ListAllMyBuckets
  * s3:GetBucketLocation
  * s3:GetBucketVersioning
  * s3:GetBucketEncryption

Features:
- Discovers all accessible S3 buckets in the account
- Extracts key security and configuration settings for each bucket:
  * Geographic location/region
  * Versioning status (Enabled/Suspended)
  * MFA Delete protection status
  * Server-side encryption type (AES256/aws:kms)
  * KMS key ID (if using KMS encryption)
  * Bucket Key optimization status

Output:
Generates a formatted JSON report with complete configuration details
for all buckets, suitable for security audits, compliance reporting,
or infrastructure documentation.

Usage:
    python s3_bucket_audit.py

Example output structure:
{
  "my-bucket": {
    "Bucket Location": "us-west-2",
    "Versioning Status": "Enabled",
    "MFA Delete Status": "Disabled",
    "Server Side Encryption": "aws:kms",
    "KMSMasterKeyID": "arn:aws:kms:us-west-2:123456789:key/abc-123",
    "BucketKeyEnabled": true
  }
}

"""

import json

import boto3
from botocore.exceptions import ClientError

bucket_dict = {}

# Create client session
boto3.setup_default_session()
s3client = boto3.client("s3")

# List all s3 buckets
s3_response = s3client.list_buckets()

# Create a list of bucket names
bucket_names = [bucket["Name"] for bucket in s3_response["Buckets"]]

def get_location(bucket):
    """
    Get the geographic location of the S3 bucket.

    Args:
        bucket (str): The name of the S3 bucket.

    Returns:
        str: The AWS region where the bucket is located.

    """
    bucket_location = "us-east-1"

    response = s3client.get_bucket_location(Bucket=bucket)
    if response["LocationConstraint"]:
        bucket_location = response["LocationConstraint"]

    return bucket_location

def get_versioning(bucket):
    """
    Get the versioning status of the S3 bucket.

    Args:
        bucket (str): The name of the S3 bucket.

    Returns:
        tuple: A tuple containing the versioning status and MFA delete status.

    """
    # Default values
    versioning_status = "Suspended"
    mfa_delete_status = "Disabled"

    response = s3client.get_bucket_versioning(Bucket=bucket)
    if "Status" in response:
        versioning_status = response["Status"]

    if "MFADelete" in response:
        mfa_delete_status = response["MFADelete"]

    return versioning_status, mfa_delete_status

def get_bucket_encryption(bucket):
    """
    Get the server-side encryption configuration of the S3 bucket.

    Args:
        bucket (str): The name of the S3 bucket.

    Returns:
        tuple: A tuple containing the encryption type, KMS key ID (if applicable),
               and whether bucket key optimization is enabled.

    """
    try:
        response = s3client.get_bucket_encryption(Bucket=bucket)
        encryption_config = response["ServerSideEncryptionConfiguration"]["Rules"][0]
        encryption_default = encryption_config["ApplyServerSideEncryptionByDefault"]

        encryption_type = encryption_default["SSEAlgorithm"]
        kms_key = None

        # Get KMS key if using KMS encryption
        if encryption_type != "AES256" and "KMSMasterKeyID" in encryption_default:
            kms_key = encryption_default["KMSMasterKeyID"]

        bucket_key_enabled = encryption_config.get("BucketKeyEnabled", False)

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            print(f"Info: Bucket {bucket} has no encryption configuration")
            encryption_type = "None"
        else:
            print(f"Warning: Could not get encryption for bucket {bucket}: {e}")
            encryption_type = "Unknown"
        return encryption_type, None, False

    else:
        return encryption_type, kms_key, bucket_key_enabled


for bucket in bucket_names:
    encryption_type, kms_key, bucket_key_enabled = get_bucket_encryption(bucket)
    versioning_status, mfa_delete_status = get_versioning(bucket)
    bucket_dict[bucket] = {
        "Bucket Location": get_location(bucket),
        "Versioning Status": versioning_status,
        "MFA Delete Status": mfa_delete_status,
        "Server Side Encryption": encryption_type,
        "KMSMasterKeyID": kms_key,
        "BucketKeyEnabled": bucket_key_enabled,
    }

print(json.dumps(bucket_dict, indent=2))
