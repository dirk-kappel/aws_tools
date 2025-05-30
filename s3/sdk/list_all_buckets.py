#!/usr/bin/env python3
"""
AWS S3 Bucket Lister.

A utility script that retrieves and displays all S3 buckets accessible
to the authenticated AWS account using the Boto3 SDK.

Prerequisites:
- AWS credentials configured (via AWS CLI, environment variables,
  IAM roles, or AWS credentials file)
- Boto3 library installed (pip install boto3)
- Appropriate S3 permissions (s3:ListAllMyBuckets)

Features:
- Uses default AWS session configuration
- Extracts bucket names from the S3 API response
- Returns a clean list of bucket names for easy processing
- No error handling (assumes valid AWS credentials and permissions)

Output:
Prints a Python list of all bucket names in the account, e.g.:
['my-website-bucket', 'data-backup-bucket', 'logs-bucket']

Usage:
    python list_s3_buckets.py

Note: Ensure your AWS credentials are properly configured before running.
The script will list ALL buckets in your AWS account that the authenticated
user has access to view.
"""

import boto3

# Create client session
boto3.setup_default_session()
s3client = boto3.client("s3")

# List all s3 buckets
s3_response = s3client.list_buckets()

# Create a list of bucket names
bucket_names = [bucket["Name"] for bucket in s3_response["Buckets"]]

print(bucket_names)
