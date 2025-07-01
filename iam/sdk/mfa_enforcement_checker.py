#!/usr/bin/env python3
# mfa_enforcement_checker.py
"""
AWS IAM MFA Enforcement Checker.

This script checks if IAM users have MFA (Multi-Factor Authentication) enforcement
policies attached either directly to their account or inherited through group membership.

REQUIREMENTS:
- Python 3.6+
- boto3 >= 1.35.76
- botocore >= 1.35.82
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)

AWS PERMISSIONS NEEDED:
- iam:ListUsers
- iam:ListUserPolicies
- iam:GetUserPolicy
- iam:ListAttachedUserPolicies
- iam:ListGroupsForUser
- iam:ListGroupPolicies
- iam:GetGroupPolicy
- iam:ListAttachedGroupPolicies
- iam:GetPolicy
- iam:GetPolicyVersion

WHAT IT CHECKS:
✅ User inline policies
✅ User attached managed policies
✅ Group inline policies (inherited)
✅ Group attached managed policies (inherited)
✅ User has an MFA device configured

WHAT IT DOES NOT CHECK:
❌ IAM Roles (only checks Users)
❌ Permission boundaries
❌ Resource-based policies
❌ AWS Organizations Service Control Policies (SCPs)
❌ Cross-account assume role policies
❌ Malformed or invalid policy syntax

MFA ENFORCEMENT PATTERNS DETECTED:
1. Blanket deny: Effect="Deny", Action="*", Condition with MFA check
2. NotAction deny: Effect="Deny", NotAction=[approved actions], Condition with MFA check

APPROVED NOTACTION LIST:
- iam:CreateVirtualMFADevice
- iam:EnableMFADevice
- iam:GetUser
- iam:ListMFADevices
- iam:ListVirtualMFADevices
- iam:ResyncMFADevice
- sts:GetSessionToken
"""

import csv
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

mfa_user_summary = {}
users_without_mfa = []
no_mfa_device = []
all_users = []

# Initialize IAM client
try:
    iam_client = boto3.client("iam")
except NoCredentialsError:
    print("❌ AWS credentials not found. Please configure your credentials.")
    print("   Run 'aws configure' or set environment variables.")
    sys.exit(1)

def has_api_mfa_enforcement_deny_statement(policy_document):
    """Check if policy has an MFA enforcement deny statement."""
    if "Statement" not in policy_document:
        return False

    statements = policy_document["Statement"]

    # Handle both single statement (object) and multiple statements (list)
    if not isinstance(statements, list):
        statements = [statements]

    # Check each statement for MFA enforcement
    return any(_is_mfa_deny_statement(statement) for statement in statements)

def _is_mfa_deny_statement(statement):
    """Check if a statement enforces MFA for human users."""
    # Must be a deny statement affecting all resources
    if statement.get("Effect") != "Deny" or statement.get("Resource") != "*":
        return False

    # Must have a condition block with MFA check
    if "Condition" not in statement:
        return False

    condition = statement["Condition"]
    has_mfa_condition = (("Bool" in condition and
                         condition["Bool"].get("aws:MultiFactorAuthPresent") == "false") or
                        ("BoolIfExists" in condition and
                         condition["BoolIfExists"].get("aws:MultiFactorAuthPresent") == "false"))

    if not has_mfa_condition:
        return False

    # Pattern 1: Blanket deny with Action "*" (denies everything when no MFA)
    if "Action" in statement and statement["Action"] == "*":
        return True

    # Pattern 2: NotAction deny (denies everything EXCEPT listed actions when no MFA)
    if "NotAction" in statement:
        # Define allowed actions in NotAction for MFA enforcement
        allowed_not_actions = {
            "iam:CreateVirtualMFADevice",
            "iam:EnableMFADevice",
            "iam:GetUser",
            "iam:ListMFADevices",
            "iam:ListVirtualMFADevices",
            "iam:ResyncMFADevice",
            "sts:GetSessionToken",
        }

        # Get NotAction list (handle both single string and list)
        not_actions = statement["NotAction"]
        if isinstance(not_actions, str):
            not_actions = [not_actions]

        statement_not_actions = set(not_actions)

        # Check if all actions in NotAction are in our allowed list
        unauthorized_actions = statement_not_actions - allowed_not_actions

        # Valid if no unauthorized actions found
        return len(unauthorized_actions) == 0

    return False

def _check_user_inline_policies(username):
    """Check user's inline policies for MFA enforcement."""
    inline_policies = iam_client.list_user_policies(UserName=username)
    for policy_name in inline_policies["PolicyNames"]:
        policy = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
        if has_api_mfa_enforcement_deny_statement(policy["PolicyDocument"]):
            print(f"✅ User {username} has MFA enforcement via inline policy: {policy_name}")
            return True
    return False

def _check_user_managed_policies(username):
    """Check user's attached managed policies for MFA enforcement."""
    attached_policies = iam_client.list_attached_user_policies(UserName=username)
    for policy in attached_policies["AttachedPolicies"]:
        policy_arn = policy["PolicyArn"]
        policy_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)

        if has_api_mfa_enforcement_deny_statement(policy_document["PolicyVersion"]["Document"]):
            print(f"✅ User {username} has MFA enforcement via managed policy: {policy['PolicyName']}")
            return True
    return False

def _check_user_group_policies(username):
    """Check group policies for MFA enforcement."""
    groups = iam_client.list_groups_for_user(UserName=username)
    for group in groups["Groups"]:
        group_name = group["GroupName"]

        # Check group inline policies
        group_inline_policies = iam_client.list_group_policies(GroupName=group_name)
        for policy_name in group_inline_policies["PolicyNames"]:
            policy = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
            if has_api_mfa_enforcement_deny_statement(policy["PolicyDocument"]):
                print(f"✅ User {username} has MFA enforcement via group '{group_name}' inline policy: {policy_name}")
                return True

        # Check group attached managed policies
        group_attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
        for policy in group_attached_policies["AttachedPolicies"]:
            policy_arn = policy["PolicyArn"]
            policy_version = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            policy_document = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)

            if has_api_mfa_enforcement_deny_statement(policy_document["PolicyVersion"]["Document"]):
                print(f"✅ User {username} has MFA enforcement via group '{group_name}' managed policy: {policy['PolicyName']}")
                return True
    return False

def check_user_mfa_enforcement(username):
    """Check if a specific IAM user has MFA enforcement policies."""
    try:
        # Check user's inline policies
        if _check_user_inline_policies(username):
            mfa_user_summary[username]["MFA_Enforcement"] = "True"
            return True

        # Check user's attached managed policies
        if _check_user_managed_policies(username):
            mfa_user_summary[username]["MFA_Enforcement"] = "True"
            return True

        # Check group policies
        if _check_user_group_policies(username):
            mfa_user_summary[username]["MFA_Enforcement"] = "True"
            return True

    except ClientError as e:
        print(f"Error checking user {username}: {e}")
        return False

    else:
        print(f"❌ User {username} does NOT have MFA enforcement")
        mfa_user_summary[username]["MFA_Enforcement"] = "False"
        return False

def check_all_users_mfa_enforcement():
    """Check MFA enforcement for all IAM users."""
    try:
        # Use paginator to handle accounts with many users
        paginator = iam_client.get_paginator("list_users")

        for page in paginator.paginate():
            all_users.extend(page["Users"])

        print(f"Checking MFA enforcement for {len(all_users)} users...\n")

        for user in all_users:
            username = user["UserName"]
            mfa_user_summary[username] = {}

            # Check console access
            check_console_access(username)

            # Check MFA enforcement policy
            if not check_user_mfa_enforcement(username):
                users_without_mfa.append(username)

            # Check MFA device configured
            if not get_mfa_device(username):
                no_mfa_device.append(username)

    except ClientError as e:
        print(f"Error: {e}")
    else:
        return mfa_user_summary

def get_mfa_device(username):
    """
    Get the MFA device for the current user.

    Args:
        username (str): The IAM username to check for MFA device.

    Returns:
        dict: The MFA device details if found, otherwise None.

    """
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        if response["MFADevices"]:
            print(f"✅ MFA device found for user '{username}'")
            mfa_user_summary[username]["MFA_Device_Configured"] = "True"
            return response["MFADevices"][0]
    except ClientError as e:
        print(f"Error retrieving MFA devices: {e}")
        return None
    else:
        print(f"❌ No MFA device found for user '{username}'")
        mfa_user_summary[username]["MFA_Device_Configured"] = "False"
        return None

def generate_csv():
    """Generate a CSV summary of MFA enforcement status for all users."""
    try:
        # Generate timestamped filename
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"mfa_summary_{timestamp}.csv"

        with Path(filename).open("w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)

            # Write header
            writer.writerow(["User Name", "Console Access", "MFA Console Configured", "MFA Enforcement Policy"])

            # Write user data
            for username, details in mfa_user_summary.items():
                console_access = details.get("Console_Access", "Unknown")
                mfa_device_status = details.get("MFA_Device_Configured", "Unknown")
                mfa_enforcement_status = details.get("MFA_Enforcement", "Unknown")
                writer.writerow([username, console_access,  mfa_device_status, mfa_enforcement_status])

    except (OSError, PermissionError) as e:
        print(f"❌ File system error generating CSV: {e}")
        return None
    except (TypeError, UnicodeEncodeError) as e:
        print(f"❌ Data encoding error generating CSV: {e}")
        return None

    else:
        print(f"\n✅ CSV summary generated: {filename}")
        return filename

def print_mfa_summary():
    """Print a summary of MFA enforcement status for all users."""
    print("\n" + "="*50)
    print(f"SUMMARY: {len(no_mfa_device)} of {len(all_users)} users do not have MFA device configured for console access")

    if no_mfa_device:
        print("\nUsers without an MFA device configured:")
        for username in no_mfa_device:
            print(f"  - {username}")

        print("\n" + "-"*50)
        print("REMEDIATION STEPS:")
        print("  1. Users need to configure an MFA device in the AWS Management Console")
        print("     (see https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html for details)")
        print("  2. Re-run this script to verify MFA enforcement is now detected")

    print(f"\n{'='*50}")
    print(f"SUMMARY: {len(users_without_mfa)} of {len(all_users)} users lack MFA enforcement")

    if users_without_mfa:
        print("\nUsers without MFA enforcement policy for Access Key usage:")
        for username in users_without_mfa:
            print(f"  - {username}")

        print("\n" + "-"*50)
        print("REMEDIATION STEPS:")
        print("  1. Create an inline policy OR custom managed policy with your MFA enforcement document")
        print("     (see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage-mfa-only.html for details)")
        print("  2. Attach the policy directly to users OR to groups that users belong to")
        print("  3. Re-run this script to verify MFA enforcement is now detected")

def check_console_access(username):
    """Check if user has console access (login profile)."""
    try:
        iam_client.get_login_profile(UserName=username)
        print(f"✅ User {username} has console access")
        mfa_user_summary[username]["Console_Access"] = "True"
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            print(f"❌ User {username} has no console access")
            mfa_user_summary[username]["Console_Access"] = "False"
            return False
        print(f"Error checking console access for {username}: {e}")
        mfa_user_summary[username]["Console_Access"] = "Error"
        return False
    else:
        return True

if __name__ == "__main__":
    # Check all users
    check_all_users_mfa_enforcement()
    print_mfa_summary()
    generate_csv()
