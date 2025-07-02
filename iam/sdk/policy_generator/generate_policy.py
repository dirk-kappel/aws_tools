#!/usr/bin/env python3
# least_privilege_policy_generator.py
"""
Enhanced Least Privilege Policy Generator from CloudTrail Analysis.

Reads CloudTrail analysis files and generates minimal IAM policies based on actual usage.
Optimized for AWS IAM console compatibility with comprehensive service mappings.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Constants
MIN_RESOURCE_NAME_LENGTH = 3
PREVIEW_ACTIONS_COUNT = 5
MAX_POLICY_SIZE = 6144  # AWS IAM policy size limit in characters
MAX_ACTIONS_PER_STATEMENT = 100  # Reasonable limit for readability
MIN_ARN_PARTS = 3  # Minimum parts in ARN for service extraction
MIN_ARN_FORMAT_PARTS = 6  # Minimum parts for valid ARN format


@dataclass
class PolicyStatement:
    """Represents an IAM policy statement with AWS best practices."""

    effect: str = "Allow"
    actions: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    conditions: dict = field(default_factory=dict)
    statement_id: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary format for JSON serialization."""
        statement = {
            "Effect": self.effect,
            "Action": sorted(self.actions),
        }

        # Add Sid for better organization
        if self.statement_id:
            statement["Sid"] = self.statement_id

        # Handle resources
        if self.resources:
            if len(self.resources) == 1 and "*" in self.resources:
                statement["Resource"] = "*"
            else:
                statement["Resource"] = sorted(self.resources)
        else:
            statement["Resource"] = "*"

        # Add conditions if present
        if self.conditions:
            statement["Condition"] = self.conditions

        return statement

    def estimated_size(self) -> int:
        """Estimate the JSON size of this statement."""
        return len(json.dumps(self.to_dict(), separators=(",", ":")))


class EnhancedCloudTrailToIAMMapper:
    """Enhanced mapper with comprehensive CloudTrail to IAM action mappings."""

    def __init__(self):
        """Initialize with comprehensive service mappings."""
        self.event_to_action_map = self._build_comprehensive_mappings()
        self.resource_patterns = self._build_resource_patterns()
        self.wildcard_operations = self._build_wildcard_operations()

    def _build_comprehensive_mappings(self) -> dict[str, list[str]]:
        """Build comprehensive CloudTrail event to IAM action mappings."""
        return {
            # S3 - Complete mapping
            "s3:GetBucketVersioning": ["s3:GetBucketVersioning"],
            "s3:GetBucketLocation": ["s3:GetBucketLocation"],
            "s3:ListBucket": ["s3:ListBucket"],
            "s3:GetObject": ["s3:GetObject"],
            "s3:PutObject": ["s3:PutObject"],
            "s3:DeleteObject": ["s3:DeleteObject"],
            "s3:GetBucketPolicy": ["s3:GetBucketPolicy"],
            "s3:PutBucketPolicy": ["s3:PutBucketPolicy"],
            "s3:GetBucketAcl": ["s3:GetBucketAcl"],
            "s3:PutBucketAcl": ["s3:PutBucketAcl"],
            "s3:CreateBucket": ["s3:CreateBucket"],
            "s3:DeleteBucket": ["s3:DeleteBucket"],
            "s3:GetBucketLogging": ["s3:GetBucketLogging"],
            "s3:PutBucketLogging": ["s3:PutBucketLogging"],
            "s3:GetBucketNotification": ["s3:GetBucketNotification"],
            "s3:PutBucketNotification": ["s3:PutBucketNotification"],
            "s3:GetBucketCors": ["s3:GetBucketCORS"],
            "s3:PutBucketCors": ["s3:PutBucketCORS"],
            "s3:GetBucketWebsite": ["s3:GetBucketWebsite"],
            "s3:PutBucketWebsite": ["s3:PutBucketWebsite"],
            "s3:GetBucketEncryption": ["s3:GetEncryptionConfiguration"],
            "s3:PutBucketEncryption": ["s3:PutEncryptionConfiguration"],
            "s3:GetObjectAcl": ["s3:GetObjectAcl"],
            "s3:PutObjectAcl": ["s3:PutObjectAcl"],
            "s3:GetObjectTagging": ["s3:GetObjectTagging"],
            "s3:PutObjectTagging": ["s3:PutObjectTagging"],
            "s3:GetObjectVersion": ["s3:GetObjectVersion"],
            "s3:DeleteObjectVersion": ["s3:DeleteObjectVersion"],
            "s3:ListMultipartUploads": ["s3:ListMultipartUploadParts"],
            "s3:AbortMultipartUpload": ["s3:AbortMultipartUpload"],
            "s3:CompleteMultipartUpload": ["s3:PutObject"],

            # EC2 - Comprehensive mapping
            "ec2:DescribeInstances": ["ec2:DescribeInstances"],
            "ec2:RunInstances": ["ec2:RunInstances"],
            "ec2:TerminateInstances": ["ec2:TerminateInstances"],
            "ec2:StartInstances": ["ec2:StartInstances"],
            "ec2:StopInstances": ["ec2:StopInstances"],
            "ec2:RebootInstances": ["ec2:RebootInstances"],
            "ec2:DescribeImages": ["ec2:DescribeImages"],
            "ec2:DescribeSecurityGroups": ["ec2:DescribeSecurityGroups"],
            "ec2:CreateSecurityGroup": ["ec2:CreateSecurityGroup"],
            "ec2:DeleteSecurityGroup": ["ec2:DeleteSecurityGroup"],
            "ec2:AuthorizeSecurityGroupIngress": ["ec2:AuthorizeSecurityGroupIngress"],
            "ec2:RevokeSecurityGroupIngress": ["ec2:RevokeSecurityGroupIngress"],
            "ec2:AuthorizeSecurityGroupEgress": ["ec2:AuthorizeSecurityGroupEgress"],
            "ec2:RevokeSecurityGroupEgress": ["ec2:RevokeSecurityGroupEgress"],
            "ec2:DescribeVpcs": ["ec2:DescribeVpcs"],
            "ec2:DescribeSubnets": ["ec2:DescribeSubnets"],
            "ec2:CreateVpc": ["ec2:CreateVpc"],
            "ec2:DeleteVpc": ["ec2:DeleteVpc"],
            "ec2:CreateSubnet": ["ec2:CreateSubnet"],
            "ec2:DeleteSubnet": ["ec2:DeleteSubnet"],
            "ec2:DescribeVolumes": ["ec2:DescribeVolumes"],
            "ec2:CreateVolume": ["ec2:CreateVolume"],
            "ec2:DeleteVolume": ["ec2:DeleteVolume"],
            "ec2:AttachVolume": ["ec2:AttachVolume"],
            "ec2:DetachVolume": ["ec2:DetachVolume"],
            "ec2:DescribeSnapshots": ["ec2:DescribeSnapshots"],
            "ec2:CreateSnapshot": ["ec2:CreateSnapshot"],
            "ec2:DeleteSnapshot": ["ec2:DeleteSnapshot"],
            "ec2:DescribeKeyPairs": ["ec2:DescribeKeyPairs"],
            "ec2:CreateKeyPair": ["ec2:CreateKeyPair"],
            "ec2:DeleteKeyPair": ["ec2:DeleteKeyPair"],
            "ec2:DescribeNetworkInterfaces": ["ec2:DescribeNetworkInterfaces"],
            "ec2:CreateNetworkInterface": ["ec2:CreateNetworkInterface"],
            "ec2:DeleteNetworkInterface": ["ec2:DeleteNetworkInterface"],
            "ec2:AttachNetworkInterface": ["ec2:AttachNetworkInterface"],
            "ec2:DetachNetworkInterface": ["ec2:DetachNetworkInterface"],

            # IAM - Complete mapping
            "iam:GetUser": ["iam:GetUser"],
            "iam:ListUsers": ["iam:ListUsers"],
            "iam:CreateUser": ["iam:CreateUser"],
            "iam:DeleteUser": ["iam:DeleteUser"],
            "iam:UpdateUser": ["iam:UpdateUser"],
            "iam:GetRole": ["iam:GetRole"],
            "iam:ListRoles": ["iam:ListRoles"],
            "iam:CreateRole": ["iam:CreateRole"],
            "iam:DeleteRole": ["iam:DeleteRole"],
            "iam:UpdateRole": ["iam:UpdateRole"],
            "iam:GetPolicy": ["iam:GetPolicy"],
            "iam:ListPolicies": ["iam:ListPolicies"],
            "iam:CreatePolicy": ["iam:CreatePolicy"],
            "iam:DeletePolicy": ["iam:DeletePolicy"],
            "iam:AttachRolePolicy": ["iam:AttachRolePolicy"],
            "iam:DetachRolePolicy": ["iam:DetachRolePolicy"],
            "iam:AttachUserPolicy": ["iam:AttachUserPolicy"],
            "iam:DetachUserPolicy": ["iam:DetachUserPolicy"],
            "iam:ListAttachedRolePolicies": ["iam:ListAttachedRolePolicies"],
            "iam:ListAttachedUserPolicies": ["iam:ListAttachedUserPolicies"],
            "iam:GetAccessKeyLastUsed": ["iam:GetAccessKeyLastUsed"],
            "iam:CreateAccessKey": ["iam:CreateAccessKey"],
            "iam:DeleteAccessKey": ["iam:DeleteAccessKey"],
            "iam:UpdateAccessKey": ["iam:UpdateAccessKey"],
            "iam:ListAccessKeys": ["iam:ListAccessKeys"],
            "iam:GetGroup": ["iam:GetGroup"],
            "iam:ListGroups": ["iam:ListGroups"],
            "iam:CreateGroup": ["iam:CreateGroup"],
            "iam:DeleteGroup": ["iam:DeleteGroup"],
            "iam:AddUserToGroup": ["iam:AddUserToGroup"],
            "iam:RemoveUserFromGroup": ["iam:RemoveUserFromGroup"],

            # STS - Complete mapping
            "sts:AssumeRole": ["sts:AssumeRole"],
            "sts:GetCallerIdentity": ["sts:GetCallerIdentity"],
            "sts:DecodeAuthorizationMessage": ["sts:DecodeAuthorizationMessage"],
            "sts:GetAccessKeyInfo": ["sts:GetAccessKeyInfo"],
            "sts:GetSessionToken": ["sts:GetSessionToken"],
            "sts:AssumeRoleWithWebIdentity": ["sts:AssumeRoleWithWebIdentity"],
            "sts:AssumeRoleWithSAML": ["sts:AssumeRoleWithSAML"],

            # Lambda - Complete mapping
            "lambda:ListFunctions": ["lambda:ListFunctions"],
            "lambda:GetFunction": ["lambda:GetFunction"],
            "lambda:CreateFunction": ["lambda:CreateFunction"],
            "lambda:UpdateFunctionCode": ["lambda:UpdateFunctionCode"],
            "lambda:UpdateFunctionConfiguration": ["lambda:UpdateFunctionConfiguration"],
            "lambda:DeleteFunction": ["lambda:DeleteFunction"],
            "lambda:InvokeFunction": ["lambda:InvokeFunction"],
            "lambda:GetPolicy": ["lambda:GetPolicy"],
            "lambda:AddPermission": ["lambda:AddPermission"],
            "lambda:RemovePermission": ["lambda:RemovePermission"],
            "lambda:CreateEventSourceMapping": ["lambda:CreateEventSourceMapping"],
            "lambda:DeleteEventSourceMapping": ["lambda:DeleteEventSourceMapping"],
            "lambda:GetEventSourceMapping": ["lambda:GetEventSourceMapping"],
            "lambda:ListEventSourceMappings": ["lambda:ListEventSourceMappings"],

            # CloudFormation - Complete mapping
            "cloudformation:DescribeStacks": ["cloudformation:DescribeStacks"],
            "cloudformation:ListStacks": ["cloudformation:ListStacks"],
            "cloudformation:CreateStack": ["cloudformation:CreateStack"],
            "cloudformation:UpdateStack": ["cloudformation:UpdateStack"],
            "cloudformation:DeleteStack": ["cloudformation:DeleteStack"],
            "cloudformation:DescribeStackResources": ["cloudformation:DescribeStackResources"],
            "cloudformation:DescribeStackEvents": ["cloudformation:DescribeStackEvents"],
            "cloudformation:GetTemplate": ["cloudformation:GetTemplate"],
            "cloudformation:ValidateTemplate": ["cloudformation:ValidateTemplate"],
            "cloudformation:CreateChangeSet": ["cloudformation:CreateChangeSet"],
            "cloudformation:DeleteChangeSet": ["cloudformation:DeleteChangeSet"],
            "cloudformation:DescribeChangeSet": ["cloudformation:DescribeChangeSet"],
            "cloudformation:ExecuteChangeSet": ["cloudformation:ExecuteChangeSet"],

            # CloudWatch - Complete mapping
            "cloudwatch:GetMetricStatistics": ["cloudwatch:GetMetricStatistics"],
            "cloudwatch:ListMetrics": ["cloudwatch:ListMetrics"],
            "cloudwatch:PutMetricData": ["cloudwatch:PutMetricData"],
            "cloudwatch:DescribeAlarms": ["cloudwatch:DescribeAlarms"],
            "cloudwatch:PutMetricAlarm": ["cloudwatch:PutMetricAlarm"],
            "cloudwatch:DeleteAlarms": ["cloudwatch:DeleteAlarms"],
            "cloudwatch:EnableAlarmActions": ["cloudwatch:EnableAlarmActions"],
            "cloudwatch:DisableAlarmActions": ["cloudwatch:DisableAlarmActions"],

            # CloudWatch Logs - Complete mapping
            "logs:CreateLogGroup": ["logs:CreateLogGroup"],
            "logs:CreateLogStream": ["logs:CreateLogStream"],
            "logs:PutLogEvents": ["logs:PutLogEvents"],
            "logs:DescribeLogGroups": ["logs:DescribeLogGroups"],
            "logs:DescribeLogStreams": ["logs:DescribeLogStreams"],
            "logs:GetLogEvents": ["logs:GetLogEvents"],
            "logs:FilterLogEvents": ["logs:FilterLogEvents"],
            "logs:DeleteLogGroup": ["logs:DeleteLogGroup"],
            "logs:DeleteLogStream": ["logs:DeleteLogStream"],
            "logs:PutRetentionPolicy": ["logs:PutRetentionPolicy"],
            "logs:DeleteRetentionPolicy": ["logs:DeleteRetentionPolicy"],

            # RDS - Complete mapping
            "rds:DescribeDBInstances": ["rds:DescribeDBInstances"],
            "rds:CreateDBInstance": ["rds:CreateDBInstance"],
            "rds:DeleteDBInstance": ["rds:DeleteDBInstance"],
            "rds:ModifyDBInstance": ["rds:ModifyDBInstance"],
            "rds:StartDBInstance": ["rds:StartDBInstance"],
            "rds:StopDBInstance": ["rds:StopDBInstance"],
            "rds:RebootDBInstance": ["rds:RebootDBInstance"],
            "rds:DescribeDBClusters": ["rds:DescribeDBClusters"],
            "rds:CreateDBCluster": ["rds:CreateDBCluster"],
            "rds:DeleteDBCluster": ["rds:DeleteDBCluster"],
            "rds:ModifyDBCluster": ["rds:ModifyDBCluster"],
            "rds:DescribeDBSnapshots": ["rds:DescribeDBSnapshots"],
            "rds:CreateDBSnapshot": ["rds:CreateDBSnapshot"],
            "rds:DeleteDBSnapshot": ["rds:DeleteDBSnapshot"],

            # DynamoDB - Complete mapping
            "dynamodb:ListTables": ["dynamodb:ListTables"],
            "dynamodb:CreateTable": ["dynamodb:CreateTable"],
            "dynamodb:DeleteTable": ["dynamodb:DeleteTable"],
            "dynamodb:DescribeTable": ["dynamodb:DescribeTable"],
            "dynamodb:UpdateTable": ["dynamodb:UpdateTable"],
            "dynamodb:PutItem": ["dynamodb:PutItem"],
            "dynamodb:GetItem": ["dynamodb:GetItem"],
            "dynamodb:UpdateItem": ["dynamodb:UpdateItem"],
            "dynamodb:DeleteItem": ["dynamodb:DeleteItem"],
            "dynamodb:Query": ["dynamodb:Query"],
            "dynamodb:Scan": ["dynamodb:Scan"],
            "dynamodb:BatchGetItem": ["dynamodb:BatchGetItem"],
            "dynamodb:BatchWriteItem": ["dynamodb:BatchWriteItem"],
            "dynamodb:DescribeBackup": ["dynamodb:DescribeBackup"],
            "dynamodb:CreateBackup": ["dynamodb:CreateBackup"],
            "dynamodb:DeleteBackup": ["dynamodb:DeleteBackup"],

            # SNS - Complete mapping
            "sns:ListTopics": ["sns:ListTopics"],
            "sns:CreateTopic": ["sns:CreateTopic"],
            "sns:DeleteTopic": ["sns:DeleteTopic"],
            "sns:Publish": ["sns:Publish"],
            "sns:Subscribe": ["sns:Subscribe"],
            "sns:Unsubscribe": ["sns:Unsubscribe"],
            "sns:GetTopicAttributes": ["sns:GetTopicAttributes"],
            "sns:SetTopicAttributes": ["sns:SetTopicAttributes"],
            "sns:ListSubscriptions": ["sns:ListSubscriptions"],
            "sns:ListSubscriptionsByTopic": ["sns:ListSubscriptionsByTopic"],

            # SQS - Complete mapping
            "sqs:ListQueues": ["sqs:ListQueues"],
            "sqs:CreateQueue": ["sqs:CreateQueue"],
            "sqs:DeleteQueue": ["sqs:DeleteQueue"],
            "sqs:SendMessage": ["sqs:SendMessage"],
            "sqs:ReceiveMessage": ["sqs:ReceiveMessage"],
            "sqs:DeleteMessage": ["sqs:DeleteMessage"],
            "sqs:GetQueueAttributes": ["sqs:GetQueueAttributes"],
            "sqs:SetQueueAttributes": ["sqs:SetQueueAttributes"],
            "sqs:GetQueueUrl": ["sqs:GetQueueUrl"],
            "sqs:SendMessageBatch": ["sqs:SendMessage"],
            "sqs:DeleteMessageBatch": ["sqs:DeleteMessage"],

            # CloudTrail - Added mapping
            "cloudtrail:LookupEvents": ["cloudtrail:LookupEvents"],
            "cloudtrail:DescribeTrails": ["cloudtrail:DescribeTrails"],
            "cloudtrail:GetTrailStatus": ["cloudtrail:GetTrailStatus"],
            "cloudtrail:CreateTrail": ["cloudtrail:CreateTrail"],
            "cloudtrail:DeleteTrail": ["cloudtrail:DeleteTrail"],
            "cloudtrail:UpdateTrail": ["cloudtrail:UpdateTrail"],
            "cloudtrail:StartLogging": ["cloudtrail:StartLogging"],
            "cloudtrail:StopLogging": ["cloudtrail:StopLogging"],

            # KMS - Added mapping
            "kms:Decrypt": ["kms:Decrypt"],
            "kms:Encrypt": ["kms:Encrypt"],
            "kms:GenerateDataKey": ["kms:GenerateDataKey"],
            "kms:DescribeKey": ["kms:DescribeKey"],
            "kms:ListKeys": ["kms:ListKeys"],
            "kms:CreateKey": ["kms:CreateKey"],
            "kms:DeleteKey": ["kms:ScheduleKeyDeletion"],
            "kms:CreateAlias": ["kms:CreateAlias"],
            "kms:DeleteAlias": ["kms:DeleteAlias"],

            # Secrets Manager - Added mapping
            "secretsmanager:GetSecretValue": ["secretsmanager:GetSecretValue"],
            "secretsmanager:CreateSecret": ["secretsmanager:CreateSecret"],
            "secretsmanager:DeleteSecret": ["secretsmanager:DeleteSecret"],
            "secretsmanager:UpdateSecret": ["secretsmanager:UpdateSecret"],
            "secretsmanager:DescribeSecret": ["secretsmanager:DescribeSecret"],
            "secretsmanager:ListSecrets": ["secretsmanager:ListSecrets"],

            # Systems Manager (SSM) - Added mapping
            "ssm:GetParameter": ["ssm:GetParameter"],
            "ssm:GetParameters": ["ssm:GetParameters"],
            "ssm:PutParameter": ["ssm:PutParameter"],
            "ssm:DeleteParameter": ["ssm:DeleteParameter"],
            "ssm:DescribeParameters": ["ssm:DescribeParameters"],
            "ssm:GetParametersByPath": ["ssm:GetParametersByPath"],

            # API Gateway - Added mapping
            "apigateway:GET": ["apigateway:GET"],
            "apigateway:POST": ["apigateway:POST"],
            "apigateway:PUT": ["apigateway:PUT"],
            "apigateway:DELETE": ["apigateway:DELETE"],
            "apigateway:PATCH": ["apigateway:PATCH"],

            # ECS - Added mapping
            "ecs:ListClusters": ["ecs:ListClusters"],
            "ecs:DescribeClusters": ["ecs:DescribeClusters"],
            "ecs:CreateCluster": ["ecs:CreateCluster"],
            "ecs:DeleteCluster": ["ecs:DeleteCluster"],
            "ecs:ListServices": ["ecs:ListServices"],
            "ecs:DescribeServices": ["ecs:DescribeServices"],
            "ecs:CreateService": ["ecs:CreateService"],
            "ecs:DeleteService": ["ecs:DeleteService"],
            "ecs:UpdateService": ["ecs:UpdateService"],
            "ecs:ListTasks": ["ecs:ListTasks"],
            "ecs:DescribeTasks": ["ecs:DescribeTasks"],
            "ecs:RunTask": ["ecs:RunTask"],
            "ecs:StopTask": ["ecs:StopTask"],
        }

    def _build_resource_patterns(self) -> dict[str, dict[str, str]]:
        """Build resource ARN patterns for different services."""
        return {
            "s3": {
                "bucket": "arn:aws:s3:::{bucket_name}",
                "object": "arn:aws:s3:::{bucket_name}/{key}",
                "all_objects": "arn:aws:s3:::{bucket_name}/*",
            },
            "ec2": {
                "instance": "arn:aws:ec2:{region}:{account}:instance/{instance_id}",
                "security_group": "arn:aws:ec2:{region}:{account}:security-group/{sg_id}",
                "vpc": "arn:aws:ec2:{region}:{account}:vpc/{vpc_id}",
                "subnet": "arn:aws:ec2:{region}:{account}:subnet/{subnet_id}",
                "volume": "arn:aws:ec2:{region}:{account}:volume/{volume_id}",
                "snapshot": "arn:aws:ec2:{region}:{account}:snapshot/{snapshot_id}",
                "network_interface": "arn:aws:ec2:{region}:{account}:network-interface/{eni_id}",
            },
            "iam": {
                "user": "arn:aws:iam::{account}:user/{user_name}",
                "role": "arn:aws:iam::{account}:role/{role_name}",
                "policy": "arn:aws:iam::{account}:policy/{policy_name}",
                "group": "arn:aws:iam::{account}:group/{group_name}",
            },
            "lambda": {
                "function": "arn:aws:lambda:{region}:{account}:function:{function_name}",
            },
            "dynamodb": {
                "table": "arn:aws:dynamodb:{region}:{account}:table/{table_name}",
            },
            "rds": {
                "db": "arn:aws:rds:{region}:{account}:db:{db_instance_identifier}",
                "cluster": "arn:aws:rds:{region}:{account}:cluster:{cluster_identifier}",
                "snapshot": "arn:aws:rds:{region}:{account}:snapshot:{snapshot_id}",
            },
            "sns": {
                "topic": "arn:aws:sns:{region}:{account}:{topic_name}",
            },
            "sqs": {
                "queue": "arn:aws:sqs:{region}:{account}:{queue_name}",
            },
            "kms": {
                "key": "arn:aws:kms:{region}:{account}:key/{key_id}",
                "alias": "arn:aws:kms:{region}:{account}:alias/{alias_name}",
            },
            "secretsmanager": {
                "secret": "arn:aws:secretsmanager:{region}:{account}:secret:{name}-{suffix}",
            },
            "ssm": {
                "parameter": "arn:aws:ssm:{region}:{account}:parameter/{parameter_name}",
            },
            "logs": {
                "log_group": "arn:aws:logs:{region}:{account}:log-group:{log_group_name}:*",
            },
        }

    def _build_wildcard_operations(self) -> dict[str, list[str]]:
        """Build operations that should always use wildcard resources."""
        return {
            "ec2": [
                "DescribeRegions", "DescribeAvailabilityZones", "DescribeImages",
                "DescribeInstances", "DescribeSecurityGroups", "DescribeVpcs",
                "DescribeSubnets", "DescribeKeyPairs", "DescribeInstanceTypes",
                "DescribeVolumes", "DescribeSnapshots", "DescribeNetworkInterfaces",
                "DescribeRouteTables", "DescribeInternetGateways", "DescribeNatGateways",
            ],
            "iam": [
                "ListUsers", "ListRoles", "ListPolicies", "ListGroups",
                "GetAccountSummary", "GetCredentialReport", "ListAccountAliases",
                "ListAccessKeys", "ListAttachedRolePolicies", "ListAttachedUserPolicies",
            ],
            "s3": [
                "ListAllMyBuckets", "ListBuckets", "GetAccountPublicAccessBlock",
            ],
            "lambda": [
                "ListFunctions", "ListLayers", "ListEventSourceMappings",
            ],
            "rds": [
                "DescribeDBInstances", "DescribeDBClusters", "DescribeDBEngineVersions",
                "DescribeDBParameterGroups", "DescribeDBSubnetGroups",
            ],
            "cloudformation": [
                "ListStacks", "DescribeStacks", "ListStackResources",
            ],
            "cloudwatch": [
                "ListMetrics", "DescribeAlarms",
            ],
            "logs": [
                "DescribeLogGroups", "DescribeLogStreams",
            ],
            "dynamodb": [
                "ListTables",
            ],
            "sns": [
                "ListTopics", "ListSubscriptions",
            ],
            "sqs": [
                "ListQueues",
            ],
            "sts": [
                "GetCallerIdentity", "DecodeAuthorizationMessage", "GetAccessKeyInfo",
            ],
            "kms": [
                "ListKeys", "ListAliases",
            ],
            "secretsmanager": [
                "ListSecrets",
            ],
            "ssm": [
                "DescribeParameters",
            ],
            "ecs": [
                "ListClusters", "ListServices", "ListTasks",
            ],
            "cloudtrail": [
                "DescribeTrails", "GetTrailStatus",
            ],
        }

    def map_event_to_actions(self, service: str, event_name: str) -> list[str]:
        """Map CloudTrail event to IAM actions with enhanced coverage."""
        event_key = f"{service}:{event_name}"

        # Try exact match first
        if event_key in self.event_to_action_map:
            return self.event_to_action_map[event_key]

        # Try common patterns
        if (service == "s3" and event_name.startswith("Get")) or (service == "s3" and event_name.startswith("Put")):
            return [f"s3:{event_name}"]
        if service == "s3" and event_name.startswith("Delete"):
            return [f"s3:{event_name}"]

        # For other services, use direct mapping
        inferred_action = f"{service}:{event_name}"
        print(f"⚠️  No explicit mapping found for {event_key}, using: {inferred_action}")
        return [inferred_action]

    def extract_resource_arns(self, api_call_info: dict) -> list[str]:
        """Extract and construct resource ARNs with enhanced logic."""
        service = api_call_info.get("service", "").lower()
        event_name = api_call_info.get("event_name", "")
        resource_arns = set(api_call_info.get("resources", []))

        # Check if this operation should use wildcard resource
        if service in self.wildcard_operations and event_name in self.wildcard_operations[service]:
            return ["*"]

        # Filter and validate existing ARNs
        valid_arns = self._filter_and_validate_arns(resource_arns, service, event_name)
        if valid_arns:
            return list(valid_arns)

        # If no valid ARNs found, return wildcard
        return ["*"]

    def _filter_and_validate_arns(self, resource_arns: set[str], service: str, event_name: str) -> set[str]:
        """Filter and validate resource ARNs for the specific service."""
        valid_arns = set()

        for arn in resource_arns:
            if not arn or not isinstance(arn, str):
                continue

            # Skip user identity ARNs unless relevant to the operation
            if self._is_relevant_arn(arn, service, event_name) and self._is_valid_arn_format(arn):
                valid_arns.add(arn)

        return valid_arns

    def _is_relevant_arn(self, arn: str, service: str, event_name: str) -> bool:
        """Check if ARN is relevant for the service and operation."""
        if not arn.startswith("arn:aws:"):
            return False

        # Extract service from ARN
        arn_parts = arn.split(":")
        if len(arn_parts) < MIN_ARN_PARTS:
            return False

        arn_service = arn_parts[2]

        # Include ARNs that match the service
        if arn_service == service:
            return True

        # Special cases for cross-service operations
        if service == "sts" and event_name == "AssumeRole" and arn_service == "iam":
            return True

        # Include IAM ARNs for IAM operations
        return service == "iam" and arn_service == "iam"

    def _is_valid_arn_format(self, arn: str) -> bool:
        """Validate ARN format."""
        if not arn.startswith("arn:aws:"):
            return False

        parts = arn.split(":")
        return len(parts) >= MIN_ARN_FORMAT_PARTS and all(part is not None for part in parts[:5])


def load_analysis_file(file_path: Path) -> dict:
    """Load and validate CloudTrail analysis file."""
    def _raise_invalid_format():
        """Raise invalid format error."""
        error_msg = "Invalid analysis file format - missing 'activities' or 'api_calls'"
        raise ValueError(error_msg)

    try:
        with file_path.open(encoding="utf-8") as f:
            data = json.load(f)

        # Validate structure
        if "activities" not in data:
            print("⚠️  Warning: Using legacy format, looking for 'api_calls' field")
            if "api_calls" not in data:
                _raise_invalid_format()
            # Convert legacy format
            data["activities"] = data.pop("api_calls")

    except FileNotFoundError:
        print(f"❌ Analysis file not found: {file_path}")
        print("💡 Make sure you've run the CloudTrail analyzer first")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in analysis file: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)
    except (OSError, PermissionError) as e:
        print(f"❌ Error reading analysis file: {e}")
        sys.exit(1)
    else:
        return data


def generate_policy_statements(analysis_data: dict, mapper: EnhancedCloudTrailToIAMMapper) -> list[PolicyStatement]:
    """Generate optimized IAM policy statements."""
    print("🔄 Analyzing API calls and generating statements...")

    # Group actions by service and resource pattern
    service_statements = defaultdict(lambda: defaultdict(set))  # service -> resource_hash -> actions
    service_resources = defaultdict(lambda: defaultdict(set))   # service -> resource_hash -> resources

    activities = analysis_data.get("activities", {})
    total_calls = len(activities)
    processed = 0

    for call_info in activities.values():
        processed += 1
        if processed % 50 == 0 or processed == total_calls:
            print(f"   📊 Processed {processed}/{total_calls} API calls...")

        service = call_info.get("service", "").lower()
        event_name = call_info.get("event_name", "")

        if not service or not event_name:
            continue

        # Map to IAM actions
        iam_actions = mapper.map_event_to_actions(service, event_name)

        # Extract resource ARNs
        resource_arns = mapper.extract_resource_arns(call_info)

        # Create resource grouping key
        resource_key = hash(frozenset(resource_arns))

        # Group actions and resources
        service_statements[service][resource_key].update(iam_actions)
        service_resources[service][resource_key].update(resource_arns)

    # Create policy statements
    statements = []
    statement_counter = 1

    for service in sorted(service_statements.keys()):
        print(f"   🔧 Creating statements for {service.upper()}...")

        for resource_key in service_statements[service]:
            actions = service_statements[service][resource_key]
            resources = service_resources[service][resource_key]

            # Split large action sets if needed
            action_chunks = [actions] if len(actions) <= MAX_ACTIONS_PER_STATEMENT else \
                           [set(list(actions)[i:i + MAX_ACTIONS_PER_STATEMENT])
                            for i in range(0, len(actions), MAX_ACTIONS_PER_STATEMENT)]

            for chunk in action_chunks:
                statement = PolicyStatement(
                    actions=chunk,
                    resources=resources,
                    statement_id=f"{service.title()}Access{statement_counter:02d}",
                )
                statements.append(statement)
                statement_counter += 1

    print(f"✅ Generated {len(statements)} policy statements")
    return statements


def optimize_policy_size(statements: list[PolicyStatement]) -> list[PolicyStatement]:
    """Optimize policy to stay within AWS size limits."""
    total_size = sum(stmt.estimated_size() for stmt in statements)

    if total_size <= MAX_POLICY_SIZE:
        print(f"✅ Policy size: {total_size} characters (within {MAX_POLICY_SIZE} limit)")
        return statements

    print(f"⚠️  Policy size ({total_size} chars) exceeds AWS limit ({MAX_POLICY_SIZE} chars)")
    print("🔧 Optimizing policy size...")

    # Sort statements by size (largest first) for optimization
    sorted_statements = sorted(statements, key=lambda x: x.estimated_size(), reverse=True)
    optimized_statements = []
    current_size = 0

    for stmt in sorted_statements:
        stmt_size = stmt.estimated_size()
        if current_size + stmt_size <= MAX_POLICY_SIZE:
            optimized_statements.append(stmt)
            current_size += stmt_size
        else:
            print(f"⚠️  Skipping statement with {len(stmt.actions)} actions (too large)")

    final_size = sum(stmt.estimated_size() for stmt in optimized_statements)
    print(f"✅ Optimized policy size: {final_size} characters")

    if len(optimized_statements) < len(statements):
        skipped = len(statements) - len(optimized_statements)
        print(f"⚠️  Warning: {skipped} statements were skipped due to size constraints")
        print("💡 Consider creating multiple policies or using managed policies")

    return optimized_statements


def create_iam_policy(statements: list[PolicyStatement]) -> dict:
    """Create a complete IAM policy document."""
    return {
        "Version": "2012-10-17",
        "Statement": [stmt.to_dict() for stmt in statements if stmt.actions],
    }


def print_detailed_policy_summary(policy: dict, analysis_data: dict):
    """Print comprehensive policy summary with AWS-ready information."""
    statements = policy["Statement"]
    total_actions = sum(len(stmt["Action"]) for stmt in statements)

    # Get summary data
    summary = analysis_data.get("summary", {})
    user_identifier = summary.get("user_identifier", "Unknown")
    total_api_calls = summary.get("unique_api_calls", len(analysis_data.get("activities", {})))

    print(f"\n{'='*80}")
    print("🔐 LEAST PRIVILEGE POLICY GENERATED")
    print(f"{'='*80}")
    print(f"👤 User: {user_identifier}")
    print(f"📅 Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"📊 Policy Statements: {len(statements)}")
    print(f"🔧 Total IAM Actions: {total_actions}")
    print(f"📈 Based on {total_api_calls} unique API calls from CloudTrail")

    # Calculate policy size
    policy_json = json.dumps(policy, separators=(",", ":"))
    policy_size = len(policy_json)
    print(f"💾 Policy Size: {policy_size:,} characters ({policy_size/MAX_POLICY_SIZE*100:.1f}% of AWS limit)")

    print(f"\n{'='*60}")
    print("📋 STATEMENT BREAKDOWN")
    print(f"{'='*60}")

    # Group statements by service for better organization
    service_statements = defaultdict(list)
    for i, stmt in enumerate(statements):
        # Determine primary service from actions
        actions = stmt.get("Action", [])
        if actions:
            primary_service = actions[0].split(":")[0] if ":" in actions[0] else "unknown"
            service_statements[primary_service].append((i+1, stmt))

    for service in sorted(service_statements.keys()):
        service_stmts = service_statements[service]
        total_service_actions = sum(len(stmt["Action"]) for _, stmt in service_stmts)

        print(f"\n🔹 {service.upper()} Service ({len(service_stmts)} statements, {total_service_actions} actions)")
        print("-" * 50)

        for stmt_num, stmt in service_stmts:
            actions = stmt["Action"]
            resources = stmt.get("Resource", "*")

            print(f"   Statement {stmt_num}: {stmt.get('Sid', f'Statement{stmt_num}')}")
            print(f"      Actions ({len(actions)}): {', '.join(actions[:PREVIEW_ACTIONS_COUNT])}")
            if len(actions) > PREVIEW_ACTIONS_COUNT:
                print(f"         ... and {len(actions) - PREVIEW_ACTIONS_COUNT} more")

            if isinstance(resources, list):
                print(f"      Resources ({len(resources)}): {resources[0]}")
                if len(resources) > 1:
                    print(f"         ... and {len(resources) - 1} more")
            else:
                print(f"      Resources: {resources}")
            print()


def save_policy_to_file(policy: dict, output_file: Path, user_identifier: str = "Unknown") -> bool:
    """Save policy with metadata and instructions."""
    try:
        # Add metadata as comments in a separate instruction file
        instructions = {
            "policy": policy,
            "metadata": {
                "generated_on": datetime.now(timezone.utc).isoformat(),
                "user_analyzed": user_identifier,
                "policy_size_characters": len(json.dumps(policy, separators=(",", ":"))),
                "aws_size_limit": MAX_POLICY_SIZE,
                "total_statements": len(policy["Statement"]),
                "total_actions": sum(len(stmt["Action"]) for stmt in policy["Statement"]),
            },
            "instructions": {
                "how_to_use": [
                    "1. Copy the 'policy' section JSON to AWS IAM Console",
                    "2. Create a new policy or update existing one",
                    "3. Test in non-production environment first",
                    "4. Monitor CloudTrail for any denied actions",
                    "5. Adjust as needed based on application requirements",
                ],
                "important_notes": [
                    "This policy is based on observed CloudTrail activity",
                    "Some actions may require additional permissions not captured",
                    "Review and validate all permissions before production use",
                    "Consider adding condition statements for enhanced security",
                ],
            },
        }

        with output_file.open("w", encoding="utf-8") as f:
            json.dump(instructions, f, indent=2)

    except (OSError, PermissionError, json.JSONEncodeError) as e:
        print(f"❌ Error saving policy: {e}")
        return False
    else:
        print(f"✅ Complete policy and instructions saved to: {output_file}")
        return True


def save_aws_ready_policy(policy: dict, output_file: Path) -> bool:
    """Save AWS-ready policy JSON (policy only, no metadata)."""
    try:
        with output_file.open("w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)
    except (OSError, PermissionError, json.JSONEncodeError) as e:
        print(f"❌ Error saving AWS-ready policy: {e}")
        return False
    else:
        print(f"✅ AWS-ready policy saved to: {output_file}")
        return True


def _get_analysis_file_path() -> Path:
    """Get and validate the analysis file path."""
    input_file = input("📂 Enter CloudTrail analysis file path [default: user_activity_*.json]: ").strip()

    # Auto-detect analysis file if not specified
    if not input_file:
        analysis_files = list(Path().glob("user_activity_*.json"))
        if analysis_files:
            input_file = str(analysis_files[0])
            print(f"🔍 Auto-detected analysis file: {input_file}")
        else:
            input_file = "cloudtrail_analysis.json"
            print(f"📁 Using default: {input_file}")

    return Path(input_file)


def _validate_analysis_data(analysis_data: dict) -> tuple[dict, str]:
    """Validate analysis data and extract summary information."""
    activities = analysis_data.get("activities", {})
    if not activities:
        print("❌ No user activities found in analysis file")
        print("💡 Make sure you ran the CloudTrail user analyzer first")
        sys.exit(1)

    summary = analysis_data.get("summary", {})
    user_identifier = summary.get("user_identifier", "Unknown")

    print(f"✅ Loaded analysis for user: {user_identifier}")
    print(f"📈 Found {len(activities)} unique API calls to analyze")

    return activities, user_identifier


def _generate_and_optimize_policy(analysis_data: dict) -> dict:
    """Generate and optimize the IAM policy."""
    # Initialize enhanced mapper
    print("\n🔧 Initializing enhanced CloudTrail-to-IAM mapper...")
    mapper = EnhancedCloudTrailToIAMMapper()

    # Generate policy statements
    statements = generate_policy_statements(analysis_data, mapper)

    if not statements:
        print("❌ No valid policy statements could be generated")
        print("💡 Check if the analysis file contains valid API call data")
        sys.exit(1)

    # Optimize policy size
    optimized_statements = optimize_policy_size(statements)

    # Create final policy
    print("\n📋 Creating final IAM policy document...")
    return create_iam_policy(optimized_statements)


def _handle_policy_saving(policy: dict, user_identifier: str) -> None:
    """Handle saving policy files."""
    print(f"\n{'='*60}")
    print("💾 SAVE OPTIONS")
    print(f"{'='*60}")

    save_policy = input("Save policy files? (y/n) [default: y]: ").strip().lower()
    if save_policy in ["", "y", "yes"]:
        base_name = f"iam_policy_{user_identifier}".replace(" ", "_").replace("@", "_at_").replace(":", "_")

        # Save complete file with metadata
        complete_file = Path(f"{base_name}_complete.json")
        save_policy_to_file(policy, complete_file, user_identifier)

        # Save AWS-ready policy
        aws_ready_file = Path(f"{base_name}_aws_ready.json")
        save_aws_ready_policy(policy, aws_ready_file)

        print("\n📁 Files saved:")
        print(f"   📋 Complete (with metadata): {complete_file}")
        print(f"   🔗 AWS-ready (policy only): {aws_ready_file}")


def _display_policy_for_copy_paste(policy: dict) -> None:
    """Display the policy for copy-paste to AWS console."""
    show_policy = input("\n📺 Display AWS-ready policy for copy-paste? (y/n) [default: y]: ").strip().lower()
    if show_policy in ["", "y", "yes"]:
        print(f"\n{'='*80}")
        print("📋 AWS IAM POLICY (COPY THIS TO AWS CONSOLE)")
        print(f"{'='*80}")
        print("🔗 Copy the JSON below and paste directly into AWS IAM Policy Editor:")
        print("-" * 80)
        print(json.dumps(policy, indent=2))
        print("-" * 80)


def _show_final_instructions(policy: dict) -> None:
    """Show final deployment instructions."""
    print(f"\n{'='*80}")
    print("✅ POLICY GENERATION COMPLETE!")
    print(f"{'='*80}")
    print("📋 Next Steps:")
    print("   1. 📋 Copy the JSON policy above")
    print("   2. 🔗 Go to AWS IAM Console → Policies → Create Policy")
    print("   3. 📝 Choose JSON tab and paste the policy")
    print("   4. 🏷️  Name your policy (e.g., 'LeastPrivilegePolicy')")
    print("   5. 🧪 Test in non-production environment first")
    print("   6. 📊 Monitor CloudTrail for any denied actions")
    print("\n⚠️  IMPORTANT REMINDERS:")
    print("   • This policy is based on observed CloudTrail activity only")
    print("   • Some permissions may be missing for edge cases")
    print("   • Always test thoroughly before production deployment")
    print("   • Consider adding condition statements for better security")
    print(f"   • Policy size: {len(json.dumps(policy, separators=(',', ':'))) / MAX_POLICY_SIZE * 100:.1f}% of AWS limit")


def main():
    """Main function with enhanced workflow."""
    print("🔐 Enhanced Least Privilege Policy Generator")
    print("=" * 60)
    print("Generates minimal IAM policies from CloudTrail analysis")
    print("Ready for direct use in AWS IAM Console\n")

    # Get and validate input file
    analysis_file = _get_analysis_file_path()

    # Load and validate analysis data
    print("\n📊 Loading CloudTrail analysis...")
    analysis_data = load_analysis_file(analysis_file)
    activities, user_identifier = _validate_analysis_data(analysis_data)

    # Generate and optimize policy
    policy = _generate_and_optimize_policy(analysis_data)

    # Print detailed summary
    print_detailed_policy_summary(policy, analysis_data)

    # Handle saving
    _handle_policy_saving(policy, user_identifier)

    # Display for copy-paste
    _display_policy_for_copy_paste(policy)

    # Show final instructions
    _show_final_instructions(policy)


if __name__ == "__main__":
    main()
