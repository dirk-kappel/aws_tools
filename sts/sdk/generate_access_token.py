#!/usr/bin/env python3
"""
AWS STS Temporary Credentials Generator with MFA (Config-Driven).

An enhanced utility script that generates temporary AWS credentials using Multi-Factor
Authentication (MFA) via AWS Security Token Service (STS). This version uses a
configuration file to manage multiple AWS profiles, making it easy to switch between
different accounts and environments.

Purpose:
- Generate temporary AWS credentials (8-hour duration) using MFA for multiple accounts
- Provide an interactive menu to select from pre-configured AWS profiles
- Automatically construct MFA ARNs from profile configuration data
- Eliminate hardcoded values and support multiple AWS partitions (commercial/GovCloud)
- Output credentials in shell export format for easy environment setup

Prerequisites:
- AWS CLI configured with valid profiles matching those in your config file
- MFA devices configured and associated with your IAM users
- Boto3 library installed (pip install boto3)
- Configuration file: ~/.aws/mfa-profiles.json

Configuration File Structure:
Create ~/.aws/mfa-profiles.json with your profiles:
{
  "profiles": [
    {
      "name": "Production Environment",
      "profile_name": "prod.aws-profile",
      "account_number": "123456789012",
      "region": "us-east-1",
      "aws_partition": "aws",
      "authenticator_name": "username.or.device"
    }
  ]
}

Supported AWS Partitions:
- "aws" for commercial AWS regions
- "aws-us-gov" for AWS GovCloud regions
- "aws-cn" for AWS China regions

Features:
- Interactive profile selection menu with account/region display
- Dynamic MFA ARN construction from profile data
- Comprehensive error handling for AWS API and configuration issues
- Support for multiple AWS partitions and authenticator devices
- Clean exit handling with appropriate status codes
- Detailed error messages for troubleshooting

Usage:
1. Create ~/.aws/mfa-profiles.json with your profile configurations
2. Run: python generate_access_token.py
3. Select desired profile from the numbered menu
4. Enter current 6-digit MFA code when prompted
5. Copy and paste the export commands into your shell

Interactive Menu Example:
  Available AWS profiles:
  --------------------------------------------------
  1. Production Environment - 123456789012 (us-east-1)
  2. Development Environment - 987654321098 (us-west-2)
  3. GovCloud Environment - 555666777888 (us-gov-west-1)
  --------------------------------------------------
  Select profile (1-3):

Output Format:
  export AWS_ACCESS_KEY_ID=ASIA...
  export AWS_SECRET_ACCESS_KEY=...
  export AWS_SESSION_TOKEN=...
  export AWS_DEFAULT_REGION=us-east-1

Security Notes:
- Temporary credentials automatically expire after 8 hours
- Store output securely and avoid logging to files or version control
- Each profile can use different MFA devices and AWS partitions
- Configuration file should have appropriate file permissions (600)

Error Handling:
- Missing or malformed configuration files
- Invalid profile selections and MFA codes
- AWS API errors (permissions, expired tokens, etc.)
- Missing AWS CLI profiles or credentials
- Network connectivity issues

Dependencies:
- boto3: AWS SDK for Python
- pathlib: Modern path handling (Python 3.4+)
- json: Configuration file parsing
"""
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

# ----------- Variables -----------
duration_seconds = 28800 # Customize the token duration if needed

def load_profile_config():
    """Load profile configuration from ~/.aws/mfa-profiles.json."""
    config_path = Path.home() / ".aws" / "mfa-profiles.json"

    try:
        with config_path.open("r") as f:
            config = json.load(f)
        return config["profiles"]
    except FileNotFoundError:
        print(f"Error: Config file not found at {config_path}")
        print("Please create the file with your profile configurations.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config file: {e}")
        return None
    except KeyError:
        print("Error: Config file must contain a 'profiles' array")
        return None

def display_profile_menu(profiles):
    """Display available profiles and get user selection."""
    print("\nAvailable AWS profiles:")
    print("-" * 50)

    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile['name']} - {profile['account_number']} ({profile['region']})")

    print("-" * 50)

    try:
        while True:
            choice = input(f"Select profile (1-{len(profiles)}): ").strip()
            choice_num = int(choice)

            if 1 <= choice_num <= len(profiles):
                return profiles[choice_num - 1]
    except ValueError:
        print("Invalid input. Please enter a number corresponding to the profile.")
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)

def construct_mfa_arn(profile):
    """
    Construct MFA ARN from profile data.

    Args:
        profile (dict): Profile data containing account number and authenticator name.

    Returns:
        str: Constructed MFA ARN in the format:
             arn:<aws_partition>:iam::<account_number>:mfa/<authenticator_name>

    """
    return f"arn:{profile['aws_partition']}:iam::{profile['account_number']}:mfa/{profile['authenticator_name']}"

def get_session_token_with_mfa(profile_name, mfa_arn, mfa_code, region_name, duration):
    """
    Generate a session token for the current IAM user with MFA.

    Args:
        profile_name (str): AWS CLI profile name to use for the session.
        mfa_arn (str): ARN of the MFA device.
        mfa_code (str): The current MFA token code from the authenticator app.
        region_name (str): AWS region to use for the STS client (e.g., 'us-west-2').
        duration (int): Duration of the session token in seconds (up to 129,600 for IAM users).

    Returns:
        dict: Contains AccessKeyId, SecretAccessKey, and SessionToken.

    """
    # Initialize a session using the specified profile
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client("sts", region_name)

    # Get a session token with MFA
    response = sts_client.get_session_token(
        DurationSeconds=duration,
        SerialNumber=mfa_arn,
        TokenCode=mfa_code,
    )
    credentials = response["Credentials"]

    # Print the export commands to stdout so to cut and paste in friendly format.
    print("\nUse the following export commands: (Linux or MacOS)\n")
    print(f"export AWS_ACCESS_KEY_ID={credentials['AccessKeyId']}")
    print(f"export AWS_SECRET_ACCESS_KEY={credentials['SecretAccessKey']}")
    print(f"export AWS_SESSION_TOKEN={credentials['SessionToken']}")
    print(f"export AWS_DEFAULT_REGION={region_name}\n")


# Main Program Logic
if __name__ == "__main__":
    # Load profile configurations
    profiles = load_profile_config()
    if not profiles:
        sys.exit(1)

    # Display menu and get user selection
    selected_profile = display_profile_menu(profiles)
    if not selected_profile:
        sys.exit(1)

    # Extract profile data
    profile_name = selected_profile["profile_name"]
    region_name = selected_profile["region"]
    mfa_arn = construct_mfa_arn(selected_profile)

    print(f"\nUsing profile: {selected_profile['name']}")
    print(f"Account: {selected_profile['account_number']}")
    print(f"Region: {region_name}")
    print(f"MFA Device: {selected_profile['authenticator_name']}")

    # Prompt the user for the MFA code
    mfa_code = input("Enter the MFA code from your authenticator app: ")

    # Generate the session token
    try:
        token = get_session_token_with_mfa(profile_name, mfa_arn, mfa_code, region_name=region_name, duration=duration_seconds)
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidUserToken.MalformedToken":
            print("Error: Invalid MFA token. Please check your MFA code and try again.")
        elif error_code == "AccessDenied":
            print("Error: Access denied. Check your MFA device ARN and permissions.")
        elif error_code == "TokenRefreshRequired":
            print("Error: MFA token expired. Please enter a fresh MFA code.")
        else:
            print(f"AWS API Error ({error_code}): {e.response['Error']['Message']}")
    except ProfileNotFound:
        print(f"Error: AWS profile {profile_name} not found. Please check your AWS configuration.")
    except NoCredentialsError:
        print("Error: No AWS credentials found. Please configure your AWS credentials.")
    except ValueError as e:
        print(f"Error: Invalid input value - {e}")
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise
