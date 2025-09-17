#!/usr/bin/env python3
"""
End-to-end test script for the DynamoDB Streaming & SNS Notification System.

Tests the complete pipeline: DynamoDB → Streams → Lambda → SNS → SQS
"""

import json
import sys
import time
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # Update region as needed
sqs = boto3.client('sqs', region_name='us-east-1')
logs = boto3.client('logs', region_name='us-east-1')

# Configuration (update these after terraform apply)
TABLE_NAME = "messages"
SQS_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/725857994970/message-notifications-queue"  # From terraform output
LAMBDA_LOG_GROUP = "/aws/lambda/message-stream-processor"

# Get table reference
messages_table = dynamodb.Table(TABLE_NAME)

class Colors:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(title):
    """Print a formatted header."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'=' * 60}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}{title.center(60)}{Colors.END}")
    print(f"{Colors.BLUE}{Colors.BOLD}{'=' * 60}{Colors.END}\n")

def print_success(message):
    """Print success message."""
    print(f"{Colors.GREEN}✅ {message}{Colors.END}")

def print_warning(message):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.END}")

def print_error(message):
    """Print error message."""
    print(f"{Colors.RED}❌ {message}{Colors.END}")

def print_info(message):
    """Print info message."""
    print(f"{Colors.BLUE}ℹ️  {message}{Colors.END}")

def generate_message_id():
    """Generate a unique message ID."""
    return f"test_{uuid.uuid4().hex[:8]}"

def insert_test_message(author, content, reply_to_message_id=None):
    """Insert a test message into DynamoDB."""
    message_item = {
        'message_id': generate_message_id(),
        'author': author,
        'content': content,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    if reply_to_message_id:
        message_item['reply_to_message_id'] = reply_to_message_id
    
    try:
        messages_table.put_item(Item=message_item)
        print_success(f"Inserted message: {message_item['message_id']} from {author}")
        return message_item
    except ClientError as e:
        print_error(f"Failed to insert message: {e}")
        return None

def wait_and_check_sqs(expected_messages=1, max_wait_time=30):
    """Wait for messages to appear in SQS and return them."""
    print_info(f"Waiting up to {max_wait_time} seconds for {expected_messages} notification(s)...")
    
    start_time = time.time()
    received_messages = []
    
    while time.time() - start_time < max_wait_time:
        try:
            response = sqs.receive_message(
                QueueUrl=SQS_QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=2,
                MessageAttributeNames=['All']
            )
            
            if 'Messages' in response:
                for msg in response['Messages']:
                    # Parse SNS message from SQS
                    sns_message = json.loads(msg['Body'])
                    received_messages.append({
                        'subject': sns_message.get('Subject', 'N/A'),
                        'message': sns_message.get('Message', 'N/A'),
                        'attributes': sns_message.get('MessageAttributes', {}),
                        'receipt_handle': msg['ReceiptHandle']
                    })
                    
                    # Delete message from queue to avoid reprocessing
                    sqs.delete_message(
                        QueueUrl=SQS_QUEUE_URL,
                        ReceiptHandle=msg['ReceiptHandle']
                    )
                
                if len(received_messages) >= expected_messages:
                    break
            
            time.sleep(2)
            
        except ClientError as e:
            print_warning(f"Error checking SQS: {e}")
            time.sleep(2)
    
    return received_messages

def check_lambda_logs():
    """Check recent Lambda function logs."""
    print_info("Checking Lambda function logs...")
    
    try:
        # Get recent log streams
        response = logs.describe_log_streams(
            logGroupName=LAMBDA_LOG_GROUP,
            orderBy='LastEventTime',
            descending=True,
            limit=5
        )
        
        if not response['logStreams']:
            print_warning("No log streams found")
            return
        
        # Get logs from the most recent stream
        latest_stream = response['logStreams'][0]
        
        log_response = logs.get_log_events(
            logGroupName=LAMBDA_LOG_GROUP,
            logStreamName=latest_stream['logStreamName'],
            limit=20,
            startFromHead=False
        )
        
        if log_response['events']:
            print_success(f"Found {len(log_response['events'])} recent log events")
            for event in log_response['events'][-5:]:  # Show last 5 events
                timestamp = datetime.fromtimestamp(event['timestamp'] / 1000)
                print(f"    {timestamp}: {event['message'].strip()}")
        else:
            print_warning("No recent log events found")
            
    except ClientError as e:
        print_error(f"Error reading Lambda logs: {e}")

def run_basic_message_test():
    """Test basic new message functionality."""
    print_header("TEST 1: Basic New Message")
    
    # Insert a new message
    message = insert_test_message("alice_test", "Hello from Alice! This is a test message.")
    if not message:
        return False
    
    # Wait for notification
    notifications = wait_and_check_sqs(expected_messages=1)
    
    if notifications:
        notification = notifications[0]
        print_success("Received notification:")
        print(f"    Subject: {notification['subject']}")
        print(f"    Content preview: {notification['message'][:100]}...")
        
        # Check if it's the right type
        if "New Message from alice_test" in notification['subject']:
            print_success("✅ Correct notification type and author")
            return True
        else:
            print_error("❌ Incorrect notification format")
            return False
    else:
        print_error("❌ No notification received")
        return False

def run_reply_test():
    """Test reply message functionality."""
    print_header("TEST 2: Reply Message")
    
    # First, insert an original message
    original_msg = insert_test_message("bob_test", "What's everyone's favorite programming language?")
    if not original_msg:
        return False
    
    time.sleep(3)  # Give Lambda time to process the first message
    
    # Clear any notifications from the original message
    wait_and_check_sqs(expected_messages=1, max_wait_time=10)
    
    # Now insert a reply
    reply_msg = insert_test_message(
        "charlie_test", 
        "I love Python! It's so versatile and readable.",
        reply_to_message_id=original_msg['message_id']
    )
    if not reply_msg:
        return False
    
    # Wait for reply notification
    notifications = wait_and_check_sqs(expected_messages=1, max_wait_time=30)
    
    if notifications:
        notification = notifications[0]
        print_success("Received reply notification:")
        print(f"    Subject: {notification['subject']}")
        print(f"    Content preview: {notification['message'][:150]}...")
        
        # Check if it contains both original and reply content
        message_content = notification['message']
        if ("Reply from charlie_test" in notification['subject'] and 
            "bob_test" in message_content and 
            "charlie_test" in message_content and
            "Original Message:" in message_content):
            print_success("✅ Reply notification contains both original and reply content")
            return True
        else:
            print_error("❌ Reply notification format incorrect")
            print(f"Full message: {message_content}")
            return False
    else:
        print_error("❌ No reply notification received")
        return False

def main():
    """Main test function."""
    print_header("🧪 DynamoDB Streaming & SNS End-to-End Test")
    
    # Check configuration
    if "YOUR_ACCOUNT_ID" in SQS_QUEUE_URL:
        print_error("Please update SQS_QUEUE_URL with your actual queue URL")
        print_info("Get it from: terraform output sqs_queue_url")
        return
    
    test_results = []
    
    # Run tests
    try:
        # Test 1: Basic message
        result1 = run_basic_message_test()
        test_results.append(("Basic Message Test", result1))
        
        # Wait between tests
        time.sleep(5)
        
        # Test 2: Reply message
        result2 = run_reply_test()
        test_results.append(("Reply Message Test", result2))
        
    except KeyboardInterrupt:
        print_warning("\nTest interrupted by user")
        return
    except Exception as e:
        print_error(f"Unexpected error during testing: {e}")
        return
    
    # Check Lambda logs
    print_header("Lambda Function Logs")
    check_lambda_logs()
    
    # Print test summary
    print_header("🏁 Test Summary")
    all_passed = True
    for test_name, passed in test_results:
        if passed:
            print_success(f"{test_name}: PASSED")
        else:
            print_error(f"{test_name}: FAILED")
            all_passed = False
    
    if all_passed:
        print_success("\n🎉 All tests PASSED! Your DynamoDB streaming pipeline is working correctly!")
    else:
        print_error("\n❌ Some tests FAILED. Check the logs and configuration.")
    
    print_info("\n💡 Next steps:")
    print("   1. Check your email for actual notifications")
    print("   2. View CloudWatch logs for detailed Lambda execution info")
    print("   3. Try inserting messages manually using the insert_messages.py script")

if __name__ == "__main__":
    main()