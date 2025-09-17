#!/usr/bin/env python3
"""
Test script to verify SNS topic is working correctly.

Sends sample message notifications to test the notification system.
"""

import json
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# Initialize SNS client
sns = boto3.client('sns', region_name='us-east-1')  # Update region as needed
sqs = boto3.client('sqs', region_name='us-east-1')

# Configuration (update these values after terraform apply)
SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:725857994970:message-notifications"
SQS_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/725857994970/message-notifications-queue"

def format_message_notification(message_data, is_reply=False, original_message=None):
    """
    Format message data for SNS notification.
    
    Args:
        message_data (dict): The message data from DynamoDB
        is_reply (bool): Whether this is a reply to another message
        original_message (dict): Original message data if this is a reply
        
    Returns:
        tuple: (subject, formatted_message_body)
    """
    if is_reply and original_message:
        subject = f"💬 Reply from {message_data['author']}"
        body = f"""
🔔 New Reply Notification

👤 Author: {message_data['author']}
💬 Reply: {message_data['content']}
🕐 Time: {message_data['timestamp']}

📝 Original Message:
👤 Original Author: {original_message['author']}
💬 Original Content: {original_message['content']}
🕐 Original Time: {original_message['timestamp']}

Message ID: {message_data['message_id']}
Reply to: {message_data.get('reply_to_message_id', 'N/A')}
        """.strip()
    else:
        subject = f"📝 New Message from {message_data['author']}"
        body = f"""
🔔 New Message Notification

👤 Author: {message_data['author']}
💬 Content: {message_data['content']}
🕐 Time: {message_data['timestamp']}

Message ID: {message_data['message_id']}
        """.strip()
    
    return subject, body

def publish_notification(subject, message, attributes=None):
    """
    Publish a notification to the SNS topic.
    
    Args:
        subject (str): Email subject line
        message (str): Message body
        attributes (dict): Optional message attributes
        
    Returns:
        dict: SNS publish response or None if error
    """
    try:
        message_attributes = attributes or {}
        
        # Add default attributes
        message_attributes.update({
            'timestamp': {
                'DataType': 'String',
                'StringValue': datetime.now(timezone.utc).isoformat()
            },
            'source': {
                'DataType': 'String',
                'StringValue': 'test-script'
            }
        })
        
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject,
            MessageAttributes=message_attributes
        )
        
        print(f"✅ Message published successfully!")
        print(f"   Message ID: {response['MessageId']}")
        print(f"   Subject: {subject}")
        print(f"   SNS Response: HTTP {response['ResponseMetadata']['HTTPStatusCode']}")
        
        return response
        
    except ClientError as e:
        print(f"❌ Error publishing to SNS: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return None

def check_sqs_messages(max_messages=5):
    """
    Check for messages in the SQS queue (for testing purposes).
    
    Args:
        max_messages (int): Maximum number of messages to retrieve
        
    Returns:
        list: List of received messages
    """
    try:
        response = sqs.receive_message(
            QueueUrl=SQS_QUEUE_URL,
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=2  # Short polling
        )
        
        messages = response.get('Messages', [])
        
        if messages:
            print(f"📨 Found {len(messages)} message(s) in SQS queue:")
            for i, msg in enumerate(messages, 1):
                print(f"\n   Message {i}:")
                # Parse SNS message from SQS
                sns_message = json.loads(msg['Body'])
                print(f"   Subject: {sns_message.get('Subject', 'N/A')}")
                print(f"   Message: {sns_message.get('Message', 'N/A')[:100]}...")
                print(f"   Timestamp: {sns_message.get('Timestamp', 'N/A')}")
        else:
            print("📭 No messages found in SQS queue")
            
        return messages
        
    except ClientError as e:
        print(f"❌ Error reading from SQS: {e.response['Error']['Message']}")
        return []
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return []

def test_message_notifications():
    """Test different types of message notifications."""
    print("🧪 Testing SNS Message Notifications")
    print("=" * 40)
    
    # Test 1: New message notification
    print("\n📝 Test 1: New Message Notification")
    sample_message = {
        'message_id': 'msg_test_001',
        'author': 'alice_test',
        'content': 'This is a test message from Alice!',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    subject, body = format_message_notification(sample_message)
    publish_notification(subject, body, {
        'message_type': {'DataType': 'String', 'StringValue': 'new_message'},
        'author': {'DataType': 'String', 'StringValue': sample_message['author']}
    })
    
    # Test 2: Reply notification
    print("\n💬 Test 2: Reply Message Notification")
    original_message = {
        'message_id': 'msg_original_001',
        'author': 'bob_test',
        'content': 'Hello everyone, how is everyone doing?',
        'timestamp': '2025-09-17T09:00:00Z'
    }
    
    reply_message = {
        'message_id': 'msg_reply_001',
        'author': 'charlie_test',
        'content': 'Hi Bob! Doing great, thanks for asking!',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'reply_to_message_id': 'msg_original_001'
    }
    
    subject, body = format_message_notification(reply_message, is_reply=True, original_message=original_message)
    publish_notification(subject, body, {
        'message_type': {'DataType': 'String', 'StringValue': 'reply'},
        'author': {'DataType': 'String', 'StringValue': reply_message['author']},
        'original_author': {'DataType': 'String', 'StringValue': original_message['author']}
    })
    
    # Wait a moment and check SQS for received messages
    print("\n📨 Checking SQS queue for received messages...")
    import time
    time.sleep(3)  # Wait for message propagation
    check_sqs_messages()

def main():
    """Main function."""
    print("🚀 SNS Topic Test Script")
    print("=" * 40)
    print(f"SNS Topic ARN: {SNS_TOPIC_ARN}")
    print(f"SQS Queue URL: {SQS_QUEUE_URL}")
    print("\n⚠️  Make sure to update the ARN and URL values at the top of this script!")
    
    # Check if default values are still being used
    if "YOUR_ACCOUNT_ID" in SNS_TOPIC_ARN:
        print("\n❌ Please update SNS_TOPIC_ARN and SQS_QUEUE_URL with your actual values")
        print("   Get these from 'terraform output' after applying the SNS configuration")
        return
    
    test_message_notifications()

if __name__ == "__main__":
    main()

# Helper function to get ARNs from terraform output
def print_terraform_commands():
    """Print commands to get the required ARNs from terraform output."""
    print("\n🔧 To get the required ARNs, run:")
    print("   terraform output sns_topic_arn")
    print("   terraform output sqs_queue_url")
    print("\n   Then update the values at the top of this script.")

# Uncomment to see terraform commands
# print_terraform_commands()