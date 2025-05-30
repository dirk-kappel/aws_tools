#!/bin/bash

# Configuration
BUCKET_NAME=""
BUCKET_FOLDER=""
REGION=""

# Allow overriding via command line arguments
BUCKET_NAME=${1:-$BUCKET_NAME}
BUCKET_FOLDER=${2:-$BUCKET_FOLDER}
REGION=${3:-$REGION}

echo "Calculating size for: s3://$BUCKET_NAME/$BUCKET_FOLDER/"
echo "Region: $REGION"
echo ""

# Run the command with error handling
if ! aws s3 ls s3://$BUCKET_NAME/$BUCKET_FOLDER --region $REGION --recursive --human-readable --summarize; then
    echo "Error: Failed to access S3 bucket. Check your credentials and permissions."
    exit 1
fi