#!/bin/bash

function login_with_iam_mfa {
    user_name=$1
    mfa_serial_number=$2
    role_arn=$3

    echo "Enter your IAM user credentials"
    read -p "IAM User Name: " user_name
    read -s -p "IAM User Password: " user_password
    echo
    read -p "MFA Token Code: " mfa_token_code

    response=$(aws sts assume-role \
        --role-arn $role_arn \
        --role-session-name "GovCloudCreationSession" \
        --serial-number $mfa_serial_number \
        --token-code $mfa_token_code \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text \
        --duration-seconds 3600 \
        --duration-seconds 129600 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to assume IAM role with MFA:"
        echo "$response"
        exit 1
    fi

    access_key_id=$(echo "$response" | awk '{print $1}')
    secret_access_key=$(echo "$response" | awk '{print $2}')
    session_token=$(echo "$response" | awk '{print $3}')

    export AWS_ACCESS_KEY_ID=$access_key_id
    export AWS_SECRET_ACCESS_KEY=$secret_access_key
    export AWS_SESSION_TOKEN=$session_token

    echo "Successfully logged in with IAM user and MFA"
}

function create_new_govcloud_account {
    email=$1
    account_name=$2

    response=$(aws organizations create-gov-cloud-account \
        --email $email \
        --account-name $account_name 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to create a new GovCloud account:"
        echo "$response"
        exit 1
    fi

    account_id=$(echo "$response" | awk '/"Account":/ {print $2; exit}' | tr -d '",')
    echo "Created a new GovCloud account with Account ID: $account_id"

    echo $account_id
}

function invite_to_organization {
    account_id=$1

    response=$(aws organizations invite-account-to-organization \
        --target "Id=$account_id,Type=ACCOUNT" 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to invite the new GovCloud account to the organization:"
        echo "$response"
        exit 1
    fi

    invitation_id=$(echo "$response" | awk '/"Handshake":/ {print $2; exit}' | tr -d '",')
    echo "Invited the new GovCloud account to the organization with Invitation ID: $invitation_id"

    echo $invitation_id
}

function accept_invitation {
    invitation_id=$1

    response=$(aws organizations accept-handshake \
        --handshake-id $invitation_id 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to accept the invitation to join the organization:"
        echo "$response"
        exit 1
    fi

    echo "Accepted the invitation to join the organization"
}

function add_iam_role {
    govcloud_root_account=$1

    response=$(aws iam create-role \
        --role-name 'AWSControlTowerExecution' \
        --assume-role-policy-document '{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::'$govcloud_root_account':root"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }' 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to create IAM role 'AWSControlTowerExecution' in the new GovCloud account:"
        echo "$response"
        exit 1
    fi

    echo "Created IAM role 'AWSControlTowerExecution' in the new GovCloud account"

    response=$(aws iam attach-role-policy \
        --role-name 'AWSControlTowerExecution' \
        --policy-arn 'arn:aws-us-gov:iam::aws:policy/AdministratorAccess' 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to attach 'AdministratorAccess' policy to IAM role 'AWSControlTowerExecution' in the new GovCloud account:"
        echo "$response"
        exit 1
    fi

    echo "Attached 'AdministratorAccess' policy to IAM role 'AWSControlTowerExecution' in the new GovCloud account"
}

function delete_default_vpc {
    account_id=$1

    vpc_id=$(aws ec2 describe-vpcs \
        --query "Vpcs[?IsDefault==\`true\`].VpcId" \
        --output text \
        --profile $account_id 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to describe the default VPC in the new account:"
        echo "$vpc_id"
        exit 1
    fi

    if [[ -z $vpc_id ]]; then
        echo "No default VPC found in the new account"
        return
    fi

    response=$(aws ec2 delete-vpc --vpc-id $vpc_id --profile $account_id 2>&1)

    if [[ $? -ne 0 ]]; then
        echo "Failed to delete the default VPC in the new account:"
        echo "$response"
        exit 1
    fi

    echo "Deleted the default VPC in the new account"
}

function wait_for_account_creation {
    account_id=$1
    max_attempts=60
    sleep_duration=5
    attempt=1

    echo "Waiting for the GovCloud account creation..."

    while [[ $attempt -le $max_attempts ]]; do
        response=$(aws organizations describe-account \
            --account-id $account_id 2>&1)

        if [[ $? -eq 0 ]]; then
            account_status=$(echo "$response" | awk '/"Status":/ {print $2; exit}' | tr -d '",')
            if [[ $account_status == "SUCCEEDED" ]]; then
                echo "GovCloud account creation succeeded"
                return
            elif [[ $account_status == "FAILED" ]]; then
                echo "GovCloud account creation failed"
                exit 1
            fi
        fi

        echo "Waiting for account creation... (Attempt $attempt of $max_attempts)"
        sleep $sleep_duration
        ((attempt++))
    done

    echo "Timeout: Account creation took longer than expected"
    exit 1
}

function orchestrate_govcloud_creation {
    commercial_root_account=$1
    mfa_serial_number=$2
    role_arn=$3
    payer_account=$4
    organization_id=$5

    echo "Step 1: Logging into commercial GovCloud account with IAM User and MFA"
    login_with_iam_mfa $user_name $mfa_serial_number $role_arn
    echo "Successfully logged into commercial GovCloud account with IAM User and MFA"

    echo "Step 2: Creating a new GovCloud account"
    new_account_id=$(create_new_govcloud_account "$email" "$account_name")
    echo "Successfully requested creation of new GovCloud account"

    wait_for_account_creation $new_account_id

    echo "Step 3: Logging into the GovCloud root account with IAM User and MFA"
    login_with_iam_mfa $user_name $mfa_serial_number $role_arn
    echo "Successfully logged into the GovCloud root account with IAM User and MFA"

    echo "Step 4: Inviting the new GovCloud account into the organization"
    invitation_id=$(invite_to_organization "$new_account_id")

    echo "Step 5: Accepting the invitation to join the organization"
    accept_invitation $invitation_id

    echo "Step 6: Adding an IAM role for AWSControlTowerExecution in the new GovCloud account"
    add_iam_role $govcloud_root_account

    echo "Step 7: Deleting the default VPC in the new account"
    delete_default_vpc $new_account_id

    echo "Reminder: Enroll the new account in AWS Control Tower by logging into the GovCloud root account"
}

function main {
    commercial_root_account=$1
    mfa_serial_number=$2
    role_arn=$3
    govcloud_root_account=$4

    orchestrate_govcloud_creation \
        $commercial_root_account \
        $mfa_serial_number \
        $role_arn \
        $govcloud_root_account

    echo "Script completed successfully."
}

commercial_root_account='12345678912'
mfa_serial_number='arn:aws:iam::12345678912:mfa/user_name'
role_arn='arn:aws:iam::12345678912:role/GovCloudCreationRole'
govcloud_root_account='12345678912'

main \
    $commercial_root_account \
    $mfa_serial_number \
    $role_arn \
    $govcloud_root_account