#!/usr/bin/env python3
# least_privilege_policy_generator.py
"""
Least Privilege Policy Generator from CloudTrail Analysis.

Reads CloudTrail analysis files and generates minimal IAM policies based on actual usage.
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
PREVIEW_ACTIONS_COUNT = 3


@dataclass
class PolicyStatement:
    """Represents an IAM policy statement."""

    effect: str = "Allow"
    actions: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    conditions: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary format for JSON serialization."""
        statement = {
            "Effect": self.effect,
            "Action": sorted(self.actions),
        }

        if self.resources:
            if len(self.resources) == 1 and "*" in self.resources:
                statement["Resource"] = "*"
            else:
                statement["Resource"] = sorted(self.resources)
        else:
            statement["Resource"] = "*"

        if self.conditions:
            statement["Condition"] = self.conditions

        return statement


class CloudTrailToIAMMapper:
    """Maps CloudTrail events to IAM actions."""

    def __init__(self):
        """Initialize the mapper with CloudTrail to IAM action mappings."""
        # Comprehensive mapping of CloudTrail events to IAM actions
        # Format: "service:event" -> ["iam:action1", "iam:action2"]
        self.event_to_action_map = {
            # S3 mappings
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

            # EC2 mappings
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
            "ec2:DescribeVpcs": ["ec2:DescribeVpcs"],
            "ec2:DescribeSubnets": ["ec2:DescribeSubnets"],
            "ec2:CreateVpc": ["ec2:CreateVpc"],
            "ec2:DeleteVpc": ["ec2:DeleteVpc"],

            # IAM mappings
            "iam:GetUser": ["iam:GetUser"],
            "iam:ListUsers": ["iam:ListUsers"],
            "iam:CreateUser": ["iam:CreateUser"],
            "iam:DeleteUser": ["iam:DeleteUser"],
            "iam:GetRole": ["iam:GetRole"],
            "iam:ListRoles": ["iam:ListRoles"],
            "iam:CreateRole": ["iam:CreateRole"],
            "iam:DeleteRole": ["iam:DeleteRole"],
            "iam:AssumeRole": ["sts:AssumeRole"],
            "iam:GetPolicy": ["iam:GetPolicy"],
            "iam:ListPolicies": ["iam:ListPolicies"],
            "iam:CreatePolicy": ["iam:CreatePolicy"],
            "iam:DeletePolicy": ["iam:DeletePolicy"],
            "iam:AttachRolePolicy": ["iam:AttachRolePolicy"],
            "iam:DetachRolePolicy": ["iam:DetachRolePolicy"],
            "iam:ListAttachedRolePolicies": ["iam:ListAttachedRolePolicies"],
            "iam:GetAccessKeyLastUsed": ["iam:GetAccessKeyLastUsed"],

            # STS mappings
            "sts:AssumeRole": ["sts:AssumeRole"],
            "sts:GetCallerIdentity": ["sts:GetCallerIdentity"],
            "sts:DecodeAuthorizationMessage": ["sts:DecodeAuthorizationMessage"],
            "sts:GetAccessKeyInfo": ["sts:GetAccessKeyInfo"],
            "sts:GetSessionToken": ["sts:GetSessionToken"],

            # CloudFormation mappings
            "cloudformation:DescribeStacks": ["cloudformation:DescribeStacks"],
            "cloudformation:ListStacks": ["cloudformation:ListStacks"],
            "cloudformation:CreateStack": ["cloudformation:CreateStack"],
            "cloudformation:UpdateStack": ["cloudformation:UpdateStack"],
            "cloudformation:DeleteStack": ["cloudformation:DeleteStack"],
            "cloudformation:DescribeStackResources": ["cloudformation:DescribeStackResources"],

            # Lambda mappings
            "lambda:ListFunctions": ["lambda:ListFunctions"],
            "lambda:GetFunction": ["lambda:GetFunction"],
            "lambda:CreateFunction": ["lambda:CreateFunction"],
            "lambda:UpdateFunctionCode": ["lambda:UpdateFunctionCode"],
            "lambda:DeleteFunction": ["lambda:DeleteFunction"],
            "lambda:InvokeFunction": ["lambda:InvokeFunction"],

            # CloudWatch mappings
            "cloudwatch:GetMetricStatistics": ["cloudwatch:GetMetricStatistics"],
            "cloudwatch:ListMetrics": ["cloudwatch:ListMetrics"],
            "cloudwatch:PutMetricData": ["cloudwatch:PutMetricData"],
            "cloudwatch:DescribeAlarms": ["cloudwatch:DescribeAlarms"],
            "cloudwatch:PutMetricAlarm": ["cloudwatch:PutMetricAlarm"],

            # CloudWatch Logs mappings
            "logs:CreateLogGroup": ["logs:CreateLogGroup"],
            "logs:CreateLogStream": ["logs:CreateLogStream"],
            "logs:PutLogEvents": ["logs:PutLogEvents"],
            "logs:DescribeLogGroups": ["logs:DescribeLogGroups"],
            "logs:DescribeLogStreams": ["logs:DescribeLogStreams"],

            # RDS mappings
            "rds:DescribeDBInstances": ["rds:DescribeDBInstances"],
            "rds:CreateDBInstance": ["rds:CreateDBInstance"],
            "rds:DeleteDBInstance": ["rds:DeleteDBInstance"],
            "rds:ModifyDBInstance": ["rds:ModifyDBInstance"],

            # SNS mappings
            "sns:ListTopics": ["sns:ListTopics"],
            "sns:CreateTopic": ["sns:CreateTopic"],
            "sns:DeleteTopic": ["sns:DeleteTopic"],
            "sns:Publish": ["sns:Publish"],
            "sns:Subscribe": ["sns:Subscribe"],

            # SQS mappings
            "sqs:ListQueues": ["sqs:ListQueues"],
            "sqs:CreateQueue": ["sqs:CreateQueue"],
            "sqs:DeleteQueue": ["sqs:DeleteQueue"],
            "sqs:SendMessage": ["sqs:SendMessage"],
            "sqs:ReceiveMessage": ["sqs:ReceiveMessage"],
            "sqs:GetQueueAttributes": ["sqs:GetQueueAttributes"],

            # DynamoDB mappings
            "dynamodb:ListTables": ["dynamodb:ListTables"],
            "dynamodb:CreateTable": ["dynamodb:CreateTable"],
            "dynamodb:DeleteTable": ["dynamodb:DeleteTable"],
            "dynamodb:DescribeTable": ["dynamodb:DescribeTable"],
            "dynamodb:PutItem": ["dynamodb:PutItem"],
            "dynamodb:GetItem": ["dynamodb:GetItem"],
            "dynamodb:UpdateItem": ["dynamodb:UpdateItem"],
            "dynamodb:DeleteItem": ["dynamodb:DeleteItem"],
            "dynamodb:Query": ["dynamodb:Query"],
            "dynamodb:Scan": ["dynamodb:Scan"],
        }

        # Resource ARN patterns for different services
        self.resource_patterns = {
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
            },
            "iam": {
                "user": "arn:aws:iam::{account}:user/{user_name}",
                "role": "arn:aws:iam::{account}:role/{role_name}",
                "policy": "arn:aws:iam::{account}:policy/{policy_name}",
            },
            "lambda": {
                "function": "arn:aws:lambda:{region}:{account}:function:{function_name}",
            },
            "dynamodb": {
                "table": "arn:aws:dynamodb:{region}:{account}:table/{table_name}",
            },
        }

    def map_event_to_actions(self, service: str, event_name: str) -> list[str]:
        """
        Map a CloudTrail event to IAM actions.

        Args:
            service: AWS service name
            event_name: CloudTrail event name

        Returns:
            List of IAM actions

        """
        event_key = f"{service}:{event_name}"

        # Try exact match first
        if event_key in self.event_to_action_map:
            return self.event_to_action_map[event_key]

        # Try to infer action from event name
        inferred_action = f"{service}:{event_name}"
        print(f"⚠️ No mapping found for {event_key}, using inferred action: {inferred_action}")
        return [inferred_action]

    def _get_wildcard_operations(self) -> dict[str, list[str]]:
        """Get operations that always use wildcard resources."""
        return {
            "ec2": [
                "DescribeRegions", "DescribeAvailabilityZones", "DescribeImages",
                "DescribeInstances", "DescribeSecurityGroups", "DescribeVpcs",
                "DescribeSubnets", "DescribeKeyPairs", "DescribeInstanceTypes",
                "DescribeVolumes", "DescribeSnapshots", "DescribeNetworkInterfaces",
            ],
            "iam": [
                "ListUsers", "ListRoles", "ListPolicies", "ListGroups",
                "GetAccountSummary", "GetCredentialReport", "ListAccountAliases",
            ],
            "s3": [
                "ListAllMyBuckets", "ListBuckets",
            ],
            "lambda": [
                "ListFunctions", "ListLayers",
            ],
            "rds": [
                "DescribeDBInstances", "DescribeDBClusters", "DescribeDBEngineVersions",
            ],
            "cloudformation": [
                "ListStacks", "DescribeStacks",
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
                "ListTopics",
            ],
            "sqs": [
                "ListQueues",
            ],
            "sts": [
                "GetCallerIdentity", "DecodeAuthorizationMessage",
            ],
        }

    def _filter_resource_arns(self, resource_arns: set[str], service: str, event_name: str) -> set[str]:
        """Filter resource ARNs to exclude user identity ARNs."""
        filtered_arns = set()
        for arn in resource_arns:
            # Include user ARNs only for IAM user operations
            if (":user/" in arn and service == "iam" and "User" in event_name) or (":role/" in arn and (service == "iam" and "Role" in event_name)) or (service == "sts" and event_name == "AssumeRole") or (":policy/" in arn and service == "iam" and "Policy" in event_name) or f":{service}:" in arn:
                filtered_arns.add(arn)

        return filtered_arns

    def _is_valid_resource_name(self, name: str) -> bool:
        """Check if a name is a valid resource identifier."""
        return (not name.replace(".", "").replace("-", "").isdigit() and
                "=" not in name and
                not name.startswith("172.") and
                not name.startswith("AKIA") and  # Access key IDs
                not name.startswith("AROA") and  # Role IDs
                len(name) > MIN_RESOURCE_NAME_LENGTH)

    def _construct_s3_arns(self, resource_names: list[str], event_name: str) -> list[str]:
        """Construct S3 ARNs based on operation type."""
        constructed_arns = []

        # Define operation types
        bucket_level_operations = [
            "GetBucketVersioning", "GetBucketLocation", "GetBucketPolicy",
            "PutBucketPolicy", "GetBucketAcl", "PutBucketAcl",
            "GetBucketLogging", "PutBucketLogging", "GetBucketNotification",
            "PutBucketNotification", "GetBucketOwnershipControls",
            "GetBucketObjectLockConfiguration", "ListBucket",
        ]

        object_level_operations = [
            "GetObject", "PutObject", "DeleteObject", "GetObjectAcl",
            "PutObjectAcl", "GetObjectVersion", "DeleteObjectVersion",
        ]

        for name in resource_names:
            if self._is_valid_resource_name(name):
                if event_name in bucket_level_operations:
                    # Only bucket-level permission needed
                    constructed_arns.append(f"arn:aws:s3:::{name}")
                elif event_name in object_level_operations:
                    # Only object-level permission needed
                    constructed_arns.append(f"arn:aws:s3:::{name}/*")
                else:
                    # Unknown operation, add both for safety
                    constructed_arns.append(f"arn:aws:s3:::{name}")
                    constructed_arns.append(f"arn:aws:s3:::{name}/*")

        return constructed_arns

    def _construct_iam_arns(self, resource_names: list[str], event_name: str) -> list[str]:
        """Construct IAM ARNs based on operation type."""
        constructed_arns = []

        for name in resource_names:
            if self._is_valid_resource_name(name) and len(name) > 1:
                if name.startswith("arn:aws:iam"):
                    constructed_arns.append(name)
                # Determine resource type based on the event
                elif "Role" in event_name:
                    constructed_arns.append(f"arn:aws:iam::*:role/{name}")
                elif "User" in event_name:
                    constructed_arns.append(f"arn:aws:iam::*:user/{name}")
                elif "Policy" in event_name:
                    constructed_arns.append(f"arn:aws:iam::*:policy/{name}")

        return constructed_arns

    def _construct_service_arns(self, service: str, resource_names: list[str]) -> list[str]:
        """Construct ARNs for other AWS services."""
        constructed_arns = []

        for name in resource_names:
            if self._is_valid_resource_name(name):
                if service == "lambda":
                    constructed_arns.append(f"arn:aws:lambda:*:*:function:{name}")
                elif service == "dynamodb":
                    constructed_arns.append(f"arn:aws:dynamodb:*:*:table/{name}")

        return constructed_arns

    def extract_resource_arns(self, api_call_info: dict) -> list[str]:
        """
        Extract and construct resource ARNs from API call information.

        Args:
            api_call_info: Dictionary containing API call information

        Returns:
            List of resource ARNs

        """
        service = api_call_info.get("service", "").lower()
        event_name = api_call_info.get("event_name", "")
        resource_arns = set(api_call_info.get("resource_arns", []))
        resource_names = api_call_info.get("resource_names", [])

        # Check if this operation should use wildcard resource
        wildcard_operations = self._get_wildcard_operations()
        if service in wildcard_operations and event_name in wildcard_operations[service]:
            return ["*"]

        # Filter resource ARNs
        filtered_arns = self._filter_resource_arns(resource_arns, service, event_name)
        if filtered_arns:
            return list(filtered_arns)

        # Construct ARNs from resource names
        if service == "s3":
            constructed_arns = self._construct_s3_arns(resource_names, event_name)
        elif service == "iam":
            constructed_arns = self._construct_iam_arns(resource_names, event_name)
        else:
            constructed_arns = self._construct_service_arns(service, resource_names)

        # Return constructed ARNs if any, otherwise use wildcard
        return constructed_arns if constructed_arns else ["*"]


def load_analysis_file(file_path: Path) -> dict:
    """
    Load CloudTrail analysis file.

    Args:
        file_path: Path to the analysis file

    Returns:
        Dictionary containing analysis data

    """
    try:
        with file_path.open() as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ JSON decode error in {file_path}: {e}")
        sys.exit(1)
    except OSError as e:
        print(f"❌ Error loading {file_path}: {e}")
        sys.exit(1)


def generate_policy_statements(analysis_data: dict, mapper: CloudTrailToIAMMapper) -> list[PolicyStatement]:
    """
    Generate IAM policy statements from CloudTrail analysis data.

    Args:
        analysis_data: CloudTrail analysis data
        mapper: CloudTrail to IAM mapper instance

    Returns:
        List of PolicyStatement objects

    """
    # Separate statements by resource type (wildcard vs specific)
    wildcard_statements = defaultdict(lambda: PolicyStatement())
    specific_statements = defaultdict(lambda: PolicyStatement())

    api_calls = analysis_data.get("api_calls", {})

    for call_info in api_calls.values():
        service = call_info.get("service", "").lower()
        event_name = call_info.get("event_name", "")

        # Map CloudTrail event to IAM actions
        iam_actions = mapper.map_event_to_actions(service, event_name)

        # Extract resource ARNs
        resource_arns = mapper.extract_resource_arns(call_info)

        # Determine if this should use wildcard or specific resources
        if len(resource_arns) == 1 and "*" in resource_arns:
            # This operation requires wildcard permissions
            key = f"{service}_wildcard"
            wildcard_statements[key].actions.update(iam_actions)
            wildcard_statements[key].resources = {"*"}
        else:
            # This operation can use specific resources
            # Create a key based on the resource pattern for grouping
            resource_pattern = frozenset(resource_arns)
            key = f"{service}_{hash(resource_pattern)}"
            specific_statements[key].actions.update(iam_actions)
            specific_statements[key].resources.update(resource_arns)

    # Combine wildcard and specific statements
    all_statements = list(wildcard_statements.values()) + list(specific_statements.values())
    return [stmt for stmt in all_statements if stmt.actions]


def optimize_statements(statements: list[PolicyStatement]) -> list[PolicyStatement]:
    """
    Optimize policy statements by removing empty ones and sorting.

    Args:
        statements: List of PolicyStatement objects

    Returns:
        Optimized list of PolicyStatement objects

    """
    # Remove empty statements and sort actions within each statement
    optimized = []

    for statement in statements:
        if statement.actions:
            # Keep the sets but ensure they're consistent
            statement.actions = statement.actions
            statement.resources = statement.resources
            optimized.append(statement)

    return optimized


def create_iam_policy(statements: list[PolicyStatement]) -> dict:
    """
    Create a complete IAM policy document.

    Args:
        statements: List of PolicyStatement objects

    Returns:
        IAM policy document ready for AWS

    """
    return {
        "Version": "2012-10-17",
        "Statement": [stmt.to_dict() for stmt in statements if stmt.actions],
    }


def print_policy_summary(policy: dict, analysis_data: dict):
    """
    Print a summary of the generated policy.

    Args:
        policy: Generated IAM policy
        analysis_data: Original analysis data

    """
    statements = policy["Statement"]
    total_actions = sum(len(stmt["Action"]) for stmt in statements)
    total_api_calls = len(analysis_data.get("api_calls", {}))

    print(f"\n{'='*80}")
    print("📋 GENERATED POLICY SUMMARY")
    print(f"{'='*80}")
    print(f"Generated On: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Total Statements: {len(statements)}")
    print(f"Total IAM Actions: {total_actions}")
    print(f"Based on {total_api_calls} unique API calls")
    print()

    for i, stmt in enumerate(statements, 1):
        actions = stmt["Action"]
        resources = stmt.get("Resource", "*")

        print(f"📄 Statement {i}:")
        print(f"   Actions ({len(actions)}): {', '.join(actions[:PREVIEW_ACTIONS_COUNT])}")
        if len(actions) > PREVIEW_ACTIONS_COUNT:
            print(f"   ... and {len(actions) - PREVIEW_ACTIONS_COUNT} more actions")

        if isinstance(resources, list):
            print(f"   Resources ({len(resources)}): {resources[0]}")
            if len(resources) > 1:
                print(f"   ... and {len(resources) - 1} more resources")
        else:
            print(f"   Resources: {resources}")
        print()


def save_policy_to_file(policy: dict, output_file: Path) -> bool:
    """
    Save the generated policy to a file.

    Args:
        policy: Generated IAM policy document
        output_file: Output file path

    Returns:
        True if successful, False otherwise

    """
    try:
        with output_file.open("w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)
    except (OSError, json.JSONEncodeError) as e:
        print(f"❌ Error saving policy: {e}")
        return False
    else:
        print(f"✅ Policy saved to: {output_file}")
        return True


def main():
    """Main function to generate least privilege policy from CloudTrail analysis."""
    print("🔐 Least Privilege Policy Generator")
    print("=" * 60)

    # Get input file
    input_file = input("Enter CloudTrail analysis file path [default: cloudtrail_analysis.json]: ").strip()
    if not input_file:
        input_file = "cloudtrail_analysis.json"

    analysis_file = Path(input_file)

    # Load analysis data
    print(f"\n📂 Loading analysis from: {analysis_file}")
    analysis_data = load_analysis_file(analysis_file)

    if not analysis_data.get("api_calls"):
        print("❌ No API calls found in analysis file.")
        return

    print(f"📊 Found {len(analysis_data['api_calls'])} unique API calls")

    # Initialize mapper
    mapper = CloudTrailToIAMMapper()

    # Generate policy statements
    print("\n🔄 Generating IAM policy statements...")
    statements = generate_policy_statements(analysis_data, mapper)

    # Optimize statements
    print("🔧 Optimizing policy statements...")
    optimized_statements = optimize_statements(statements)

    # Create final policy
    policy = create_iam_policy(optimized_statements)

    # Print summary
    print_policy_summary(policy, analysis_data)

    # Save to file
    save_policy = input("💾 Save policy to file? (y/n) [default: y]: ").strip().lower()
    if save_policy in ["", "y", "yes"]:
        output_file = input("Enter output filename [default: iam_policy.json]: ").strip()
        if not output_file:
            output_file = "iam_policy.json"

        save_policy_to_file(policy, Path(output_file))

    # Display policy document
    show_policy = input("\n📋 Display full policy document? (y/n) [default: y]: ").strip().lower()
    if show_policy in ["", "y", "yes"]:
        print(f"\n{'='*80}")
        print("📋 IAM POLICY DOCUMENT (Ready for AWS)")
        print(f"{'='*80}")
        print(json.dumps(policy, indent=2))

    print("\n✨ Policy generation complete!")
    print("\n⚠️  IMPORTANT NOTES:")
    print("   • Review the generated policy carefully before applying")
    print("   • Test in a non-production environment first")
    print("   • Some CloudTrail events may require additional permissions")
    print("   • Consider adding conditions for enhanced security")
    print("   • Copy the JSON above and paste directly into AWS IAM console")


if __name__ == "__main__":
    main()
