#!/usr/bin/env python3

import csv
import json
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Initialize IAM client
try:
    iam_client = boto3.client("iam")  # Adjust region as needed
except NoCredentialsError:
    print("❌ AWS credentials not found. Please configure your credentials.")
    print("   Run 'aws configure' or set environment variables.")
    sys.exit(1)

def _parse_policy_document(policy_document):
    """Parse policy document from string or dict."""
    if isinstance(policy_document, str):
        return json.loads(urllib.parse.unquote(policy_document))
    return policy_document

def _get_allowed_not_actions():
    """Get the set of allowed actions in NotAction for MFA enforcement."""
    return {
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken",
    }

def _is_mfa_deny_statement(statement):
    """Check if a statement is an MFA deny statement."""
    return (statement.get("Effect") == "Deny" and
            "Condition" in statement and
            "BoolIfExists" in statement["Condition"] and
            statement["Condition"]["BoolIfExists"].get("aws:MultiFactorAuthPresent") == "false" and
            statement.get("Resource") == "*")

def _check_blanket_deny(statement):
    """Check if statement is a blanket deny and print appropriate message."""
    if "NotAction" not in statement:
        print(f"    🔒 Found blanket MFA deny statement: {statement.get('Sid', 'No Sid')}")
        print("         Type: Blanket deny (no NotAction) - overrides all other statements")
        return True

    if isinstance(statement["NotAction"], list) and len(statement["NotAction"]) == 0:
        print(f"    🔒 Found blanket MFA deny statement: {statement.get('Sid', 'No Sid')}")
        print("         Type: Blanket deny (empty NotAction) - overrides all other statements")
        return True

    return False

def _check_selective_deny(statement, allowed_not_actions):
    """Check selective deny statement and return if valid."""
    statement_not_actions = (set(statement["NotAction"])
                           if isinstance(statement["NotAction"], list)
                           else {statement["NotAction"]})

    unauthorized_actions = statement_not_actions - allowed_not_actions

    if len(unauthorized_actions) == 0:
        print(f"    🔒 Found valid selective MFA deny statement: {statement.get('Sid', 'No Sid')}")
        print(f"         NotActions: {sorted(statement_not_actions)}")
        return True, False
    print(f"    ⚠️  Found potentially problematic MFA deny statement: {statement.get('Sid', 'No Sid')}")
    print(f"         NotActions: {sorted(statement_not_actions)}")
    print(f"         Unauthorized actions: {sorted(unauthorized_actions)}")
    return False, True

def has_api_mfa_enforcement_deny_statement(policy_document):
    """Check if a policy document contains the specific MFA enforcement deny statement."""
    try:
        policy = _parse_policy_document(policy_document)

        if "Statement" not in policy or not isinstance(policy["Statement"], list):
            return False

        allowed_not_actions = _get_allowed_not_actions()
        mfa_deny_statements = []
        has_blanket_deny = False
        has_invalid_statements = False

        # Find all deny statements that enforce MFA for API calls
        for statement in policy["Statement"]:
            if _is_mfa_deny_statement(statement):
                mfa_deny_statements.append(statement)

                if _check_blanket_deny(statement):
                    has_blanket_deny = True
                else:
                    is_valid, is_invalid = _check_selective_deny(statement, allowed_not_actions)
                    if is_invalid:
                        has_invalid_statements = True

        # Determine overall policy validity
        if len(mfa_deny_statements) == 0:
            return False

        if has_blanket_deny:
            print("    ✅ Policy is VALID: Blanket deny overrides any permissive statements")
            return True

        if has_invalid_statements:
            print("    ❌ Policy is INVALID: Contains unauthorized actions without blanket deny override")
            return False

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"    ⚠️  Error parsing policy document: {e}")
        return False

    else:
        print("    ✅ Policy is VALID: All MFA deny statements contain only authorized actions")
        return True


def check_inline_policies_for_mfa_enforcement(user_name):
    """Check all inline policies for MFA enforcement deny statements."""
    try:
        response = iam_client.list_user_policies(UserName=user_name)
        policy_names = response["PolicyNames"]

        if not policy_names:
            print("    📄 No inline policies found")
            return False

        print(f"    📄 Checking {len(policy_names)} inline policy(ies)")

        for policy_name in policy_names:
            print(f"      - Checking inline policy: {policy_name}")
            policy_response = iam_client.get_user_policy(
                UserName=user_name,
                PolicyName=policy_name,
            )

            if has_api_mfa_enforcement_deny_statement(policy_response["PolicyDocument"]):
                return True

    except ClientError as e:
        print(f"    ❌ Error checking inline policies: {e.response['Error']['Message']}")
        return False
    else:
        return False

def check_custom_managed_policies_for_mfa_enforcement(user_name):
    """Check custom managed policies (non-AWS managed) for MFA enforcement deny statements."""
    try:
        response = iam_client.list_attached_user_policies(UserName=user_name)
        attached_policies = response["AttachedPolicies"]

        # Filter out AWS managed policies (they don't contain MFA enforcement)
        custom_policies = [p for p in attached_policies if not p["PolicyArn"].startswith("arn:aws:iam::aws:policy/")]

        if not custom_policies:
            print("    📋 No custom managed policies attached")
            return False

        print(f"    📋 Checking {len(custom_policies)} custom managed policy(ies)")

        for attached_policy in custom_policies:
            policy_arn = attached_policy["PolicyArn"]
            policy_name = attached_policy["PolicyName"]

            print(f"      - Checking custom managed policy: {policy_name}")

            # Get the policy metadata
            policy_response = iam_client.get_policy(PolicyArn=policy_arn)
            default_version_id = policy_response["Policy"]["DefaultVersionId"]

            # Get the policy document
            policy_version_response = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id,
            )

            if has_api_mfa_enforcement_deny_statement(policy_version_response["PolicyVersion"]["Document"]):
                return True

    except ClientError as e:
        print(f"    ❌ Error checking custom managed policies: {e.response['Error']['Message']}")
        return False
    else:
        return False

def _check_group_inline_policies(group_name):
    """Check inline policies for a specific group."""
    group_inline_response = iam_client.list_group_policies(GroupName=group_name)
    for policy_name in group_inline_response["PolicyNames"]:
        print(f"        📄 Checking group inline policy: {policy_name}")
        policy_response = iam_client.get_group_policy(
            GroupName=group_name,
            PolicyName=policy_name,
        )
        if has_api_mfa_enforcement_deny_statement(policy_response["PolicyDocument"]):
            return True
    return False

def _check_group_managed_policies(group_name):
    """Check managed policies for a specific group."""
    group_managed_response = iam_client.list_attached_group_policies(GroupName=group_name)
    custom_group_policies = [p for p in group_managed_response["AttachedPolicies"]
                           if not p["PolicyArn"].startswith("arn:aws:iam::aws:policy/")]

    for attached_policy in custom_group_policies:
        policy_arn = attached_policy["PolicyArn"]
        policy_name = attached_policy["PolicyName"]
        print(f"        📋 Checking group managed policy: {policy_name}")

        # Get the policy document
        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
        default_version_id = policy_response["Policy"]["DefaultVersionId"]

        policy_version_response = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id,
        )

        if has_api_mfa_enforcement_deny_statement(policy_version_response["PolicyVersion"]["Document"]):
            return True
    return False

def check_group_policies_for_mfa_enforcement(user_name):
    """Check all group policies (inline and managed) for MFA enforcement deny statements."""
    try:
        # Get all groups the user belongs to
        response = iam_client.list_groups_for_user(UserName=user_name)
        groups = response["Groups"]

        if not groups:
            print("    👥 User is not in any groups")
            return False

        print(f"    👥 User belongs to {len(groups)} group(s)")

        for group in groups:
            group_name = group["GroupName"]
            print(f"      - Checking group: {group_name}")

            # Check inline policies attached to the group
            if _check_group_inline_policies(group_name):
                return True

            # Check managed policies attached to the group
            if _check_group_managed_policies(group_name):
                return True

    except ClientError as e:
        print(f"    ❌ Error checking group policies: {e.response['Error']['Message']}")
        return False
    else:
        return False

def user_has_api_mfa_enforcement(user_name):
    """Check if a user has ANY custom policy that enforces MFA for API calls."""
    print(f"\n🔍 Analyzing user: {user_name}")

    # Check inline policies first
    if check_inline_policies_for_mfa_enforcement(user_name):
        print("    ✅ MFA enforcement found in user inline policies")
        return True

    # Check custom managed policies
    if check_custom_managed_policies_for_mfa_enforcement(user_name):
        print("    ✅ MFA enforcement found in user custom managed policies")
        return True

    # Check group policies (both inline and managed)
    if check_group_policies_for_mfa_enforcement(user_name):
        print("    ✅ MFA enforcement found in group policies")
        return True

    print("    ❌ NO MFA enforcement found - user can use access keys without MFA!")
    return False

def _get_user_access_key_info(user_name):
    """Get access key information for a user."""
    try:
        access_keys = iam_client.list_access_keys(UserName=user_name)
        has_access_keys = len(access_keys["AccessKeyMetadata"]) > 0
        active_access_keys = [key for key in access_keys["AccessKeyMetadata"] if key["Status"] == "Active"]

        return {
            "has_access_keys": has_access_keys,
            "active_access_keys": len(active_access_keys),
            "access_key_ids": [key["AccessKeyId"] for key in active_access_keys],
        }
    except ClientError:
        return {
            "has_access_keys": "Unknown",
            "active_access_keys": "Unknown",
            "access_key_ids": [],
        }

def _print_user_details(user):
    """Print details for a user without MFA enforcement."""
    print(f"👤 {user['user_name']}")
    create_date = user["create_date"].strftime("%Y-%m-%d") if isinstance(user["create_date"], datetime) else str(user["create_date"])
    print(f"   📅 Created: {create_date}")

    if user["last_used"] != "Never" and user["last_used"]:
        last_used = user["last_used"].strftime("%Y-%m-%d") if isinstance(user["last_used"], datetime) else str(user["last_used"])
        print(f"   🔐 Last Password Use: {last_used}")
    else:
        print(f"   🔐 Last Password Use: {user['last_used']}")

    if user["has_access_keys"] != "Unknown":
        if user["has_access_keys"]:
            print(f"   🔑 Active Access Keys: {user['active_access_keys']}")
            if user["access_key_ids"]:
                for key_id in user["access_key_ids"]:
                    print(f"       - {key_id}")
        else:
            print("   🔑 Access Keys: None")
    else:
        print("   🔑 Access Keys: Could not determine")
    print()

def _print_security_recommendations():
    """Print security risk information and recommendations."""
    print("🚨 SECURITY RISK:")
    print("Users without custom MFA enforcement can:")
    print("  • Use AWS CLI without MFA")
    print("  • Use AWS SDK without MFA")
    print("  • Make direct API calls with access keys without MFA")
    print("  • Potentially compromise your AWS account if access keys are stolen")
    print()
    print("🔧 IMMEDIATE ACTION REQUIRED:")
    print("Create and attach the MFA enforcement policy to these users:")
    print("  1. Create an inline policy OR custom managed policy with your MFA enforcement document")
    print("     (see https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_my-sec-creds-self-manage-mfa-only.html for details)")
    print("  2. Attach it to all users listed above")
    print("  3. Verify users can still set up MFA devices")
    print("  4. Test that API calls require MFA tokens\n")

def export_users_to_csv(users_without_mfa, filename=None):
    """Export users without MFA enforcement to a CSV file."""
    if not users_without_mfa:
        print("📄 No users to export - all users have MFA enforcement!")
        return None

    if filename is None:
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"users_without_mfa_{timestamp}.csv"

    try:
        with Path(filename).open("w", newline="", encoding="utf-8") as csvfile:
            fieldnames = [
                "user_name",
                "create_date",
                "last_password_used",
                "has_access_keys",
                "active_access_keys_count",
                "access_key_ids",
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for user in users_without_mfa:
                # Format dates for CSV
                create_date = (user["create_date"].strftime("%Y-%m-%d %H:%M:%S")
                             if isinstance(user["create_date"], datetime)
                             else str(user["create_date"]))

                last_used = "Never"
                if user["last_used"] != "Never" and user["last_used"]:
                    last_used = (user["last_used"].strftime("%Y-%m-%d %H:%M:%S")
                               if isinstance(user["last_used"], datetime)
                               else str(user["last_used"]))

                # Convert access key IDs list to comma-separated string
                access_key_ids = ", ".join(user["access_key_ids"]) if user["access_key_ids"] else "None"

                writer.writerow({
                    "user_name": user["user_name"],
                    "create_date": create_date,
                    "last_password_used": last_used,
                    "has_access_keys": user["has_access_keys"],
                    "active_access_keys_count": user["active_access_keys"],
                    "access_key_ids": access_key_ids,
                })

    except OSError as e:
        print(f"❌ Error writing CSV file: {e}")
        return None

    else:
        print(f"📄 Users without MFA enforcement exported to: {filename}")
        print(f"   Total users exported: {len(users_without_mfa)}")
        return filename


def find_users_without_api_mfa_enforcement():
    """Find all users who can make API calls (including access key usage) without MFA."""
    print("🔍 Scanning IAM users for API MFA enforcement policies...")
    print("🔑 This checks if users can use access keys without MFA authentication")
    print("📋 Checking: inline policies + custom managed policies + group policies")
    print("=" * 80)

    try:
        # Get all users
        paginator = iam_client.get_paginator("list_users")
        users = []

        for page in paginator.paginate():
            users.extend(page["Users"])

        users_without_api_mfa = []
        users_with_api_mfa = []

        print(f"\n📊 Found {len(users)} users to analyze...\n")

        # Check each user
        for i, user in enumerate(users, 1):
            user_name = user["UserName"]
            print(f"[{i}/{len(users)}] Analyzing user: {user_name}")

            if user_has_api_mfa_enforcement(user_name):
                users_with_api_mfa.append(user_name)
            else:
                access_key_info = _get_user_access_key_info(user_name)
                user_info = {
                    "user_name": user_name,
                    "create_date": user["CreateDate"],
                    "last_used": user.get("PasswordLastUsed", "Never"),
                }
                user_info.update(access_key_info)
                users_without_api_mfa.append(user_info)

        # Display results
        print("\n" + "=" * 80)
        print("📊 RESULTS SUMMARY - API MFA ENFORCEMENT")
        print("=" * 80)

        print(f"✅ Users WITH custom MFA enforcement: {len(users_with_api_mfa)}")
        print(f"❌ Users WITHOUT custom MFA enforcement: {len(users_without_api_mfa)}")

        if users_without_api_mfa:
            print("\n⚠️  CRITICAL SECURITY ISSUE: USERS CAN USE ACCESS KEYS WITHOUT MFA")
            print("=" * 80)
            print("These users can make AWS API calls (CLI, SDK, direct API) without MFA:")
            print("-" * 80)

            for user in users_without_api_mfa:
                _print_user_details(user)

            _print_security_recommendations()
        else:
            print("\n🎉 EXCELLENT! All users have custom MFA enforcement!")
            print("No users can bypass MFA when using access keys for API calls.")

    except ClientError as e:
        print(f"❌ Error scanning users: {e.response['Error']['Message']}")
        sys.exit(1)
    else:
        return users_without_api_mfa

def validate_target_policy():
    """Validate and explain the target MFA policy."""
    target_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowViewAccountInfo",
                "Effect": "Allow",
                "Action": "iam:ListVirtualMFADevices",
                "Resource": "*",
            },
            {
                "Sid": "AllowManageOwnVirtualMFADevice",
                "Effect": "Allow",
                "Action": ["iam:CreateVirtualMFADevice"],
                "Resource": "arn:aws-us-gov:iam::*:mfa/*",
            },
            {
                "Sid": "AllowManageOwnUserMFA",
                "Effect": "Allow",
                "Action": [
                    "iam:DeactivateMFADevice",
                    "iam:EnableMFADevice",
                    "iam:GetUser",
                    "iam:GetMFADevice",
                    "iam:ListMFADevices",
                    "iam:ResyncMFADevice",
                ],
                "Resource": "arn:aws-us-gov:iam::*:user/${aws:username}",
            },
            {
                "Sid": "DenyAllExceptListedIfNoMFA",
                "Effect": "Deny",
                "NotAction": [
                    "iam:CreateVirtualMFADevice",
                    "iam:EnableMFADevice",
                    "iam:GetUser",
                    "iam:ListMFADevices",
                    "iam:ListVirtualMFADevices",
                    "iam:ResyncMFADevice",
                    "sts:GetSessionToken",
                ],
                "Resource": "*",
                "Condition": {
                    "BoolIfExists": {
                        "aws:MultiFactorAuthPresent": "false",
                    },
                },
            },
        ],
    }

    print("🛡️  TARGET POLICY ANALYSIS:")
    print("-" * 40)
    print("✅ This custom policy enforces MFA for ALL AWS API calls including:")
    print("   • AWS CLI commands")
    print("   • AWS SDK calls")
    print("   • Direct API calls with access keys")
    print("   • Console access")
    print()
    print("🔓 The policy allows these actions WITHOUT MFA (for initial setup):")
    print("   • iam:CreateVirtualMFADevice")
    print("   • iam:EnableMFADevice")
    print("   • iam:GetUser")
    print("   • iam:ListMFADevices")
    print("   • iam:ListVirtualMFADevices")
    print("   • iam:ResyncMFADevice")
    print("   • sts:GetSessionToken")
    print()
    print("Note: AWS managed policies do not contain MFA enforcement")
    print("   Checking: user inline + user managed + group inline + group managed")
    print()

    return has_api_mfa_enforcement_deny_statement(target_policy)

def main():
    """Main execution function."""
    print("🛡️  IAM API MFA ENFORCEMENT CHECKER")
    print("📡 Finds users who can use access keys without MFA")
    print("🎯 Checks: User policies + Group policies (excludes AWS managed)")
    print("=" * 60)

    if not validate_target_policy():
        print("❌ Error: Could not validate the target MFA policy!")
        sys.exit(1)

    try:
        users_without_mfa = find_users_without_api_mfa_enforcement()

        print("✅ Analysis completed successfully!")

        if users_without_mfa:
            print(f"\n🚨 SECURITY ALERT: {len(users_without_mfa)} users found without custom MFA enforcement!")

            # Ask user if they want to export to CSV
            try:
                while True:
                    export_choice = input("\n📋 Would you like to export these users to a CSV file? (y/n): ").lower().strip()
                    if export_choice in ["y", "yes"]:
                        csv_filename = export_users_to_csv(users_without_mfa)
                        if csv_filename:
                            print(f"📋 Detailed report saved to: {csv_filename}")
                        break
                    if export_choice in ["n", "no"]:
                        print("📋 CSV export skipped.")
                        break
                    print("❌ Please enter 'y' for yes or 'n' for no.")
            except KeyboardInterrupt:
                print("\n📋 CSV export cancelled.")

            sys.exit(1)  # Exit with error code to indicate security issue
        else:
            print("\n🎉 Security check passed: All users have custom MFA enforcement!")
            sys.exit(0)

    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
        sys.exit(1)
    except ClientError as e:
        print(f"❌ Analysis failed: {e.response['Error']['Message']}")
        sys.exit(1)

if __name__ == "__main__":
    main()
