#!/bin/bash

# Run using the following command:
# source ./central-sts.sh

# Assume the CompliantFrameworkAdministratorsAccessRole in the management account
ROLE="$(aws sts assume-role --role-arn <role_arn> --role-session-name admin-access --region <aws_region> --profile <aws_profile>)"
# Temporarily store those access keys
export AWS_ACCESS_KEY_ID=$(echo "${ROLE}" | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "${ROLE}" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "${ROLE}" | jq -r '.Credentials.SessionToken')

# Display the information about the new role
New_Role="$(aws sts get-caller-identity --region <aws_region>)"
echo "---Assumed Role---"
UserId=$(echo "${New_Role}" | jq -r '.UserId')
echo "UserId:" $UserId
Account=$(echo "${New_Role}" | jq -r '.Account')
echo "Account:" $Account
Arn=$(echo "${New_Role}" | jq -r '.Arn')
echo "Arn:" $Arn

# To unset the environment variables use:
# unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN