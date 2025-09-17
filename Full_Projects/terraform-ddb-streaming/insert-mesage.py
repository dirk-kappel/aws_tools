#!/usr/bin/env python3
"""
Simple script to insert messages into DynamoDB messages table.

Supports both new messages and replies to existing messages.
"""

import json
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb', region_name='us-east-1')  # Update region as needed
table = dynamodb.Table('messages')

def generate_message_id():
    """Generate a unique message ID using UUID4."""
    return f"msg_{uuid.uuid4()}"

def get_current_timestamp():
    """Get current timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

def insert_message(author, content, reply_to_message_id=None):
    """
    Insert a new message into the DynamoDB table.
    
    Args:
        author (str): Username or name of the message author
        content (str): The message content/text
        reply_to_message_id (str, optional): ID of message being replied to
    
    Returns:
        dict: The inserted message item
    """
    message_item = {
        'message_id': generate_message_id(),
        'author': author,
        'content': content,
        'timestamp': get_current_timestamp()
    }
    
    # Add reply_to_message_id only if this is a reply
    if reply_to_message_id:
        message_item['reply_to_message_id'] = reply_to_message_id
    
    try:
        # Insert the message into DynamoDB
        response = table.put_item(Item=message_item)
        
        print(f"✅ Message inserted successfully!")
        print(f"   Message ID: {message_item['message_id']}")
        print(f"   Author: {message_item['author']}")
        print(f"   Content: {message_item['content']}")
        print(f"   Timestamp: {message_item['timestamp']}")
        if reply_to_message_id:
            print(f"   Reply to: {reply_to_message_id}")
        print(f"   DynamoDB Response: {response['ResponseMetadata']['HTTPStatusCode']}")
        
        return message_item
        
    except ClientError as e:
        print(f"❌ Error inserting message: {e.response['Error']['Message']}")
        return None
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        return None

def get_message_by_id(message_id):
    """
    Retrieve a message by its ID (useful for testing replies).
    
    Args:
        message_id (str): The message ID to retrieve
        
    Returns:
        dict: The message item or None if not found
    """
    try:
        response = table.get_item(Key={'message_id': message_id})
        return response.get('Item')
    except ClientError as e:
        print(f"❌ Error retrieving message: {e.response['Error']['Message']}")
        return None

def list_recent_messages(limit=5):
    """
    List recent messages using the timestamp index.
    
    Args:
        limit (int): Number of messages to retrieve
        
    Returns:
        list: List of message items
    """
    try:
        response = table.scan(
            IndexName='timestamp-index',
            Limit=limit
        )
        return response.get('Items', [])
    except ClientError as e:
        print(f"❌ Error listing messages: {e.response['Error']['Message']}")
        return []

def main():
    """Main function with example usage."""
    print("🚀 DynamoDB Message Insertion Script")
    print("=" * 40)
    
    # Example 1: Insert a new message
    print("\n📝 Inserting a new message...")
    message1 = insert_message(
        author="alice", 
        content="Hello everyone! This is my first message."
    )
    
    # Example 2: Insert another message
    print("\n📝 Inserting another message...")
    message2 = insert_message(
        author="bob", 
        content="Welcome to the messaging system!"
    )
    
    # Example 3: Insert a reply (if first message was successful)
    if message1:
        print("\n💬 Inserting a reply...")
        reply_message = insert_message(
            author="charlie", 
            content="Thanks Alice! Great to be here.", 
            reply_to_message_id=message1['message_id']
        )
    
    # Example 4: List recent messages
    print("\n📋 Recent messages:")
    recent_messages = list_recent_messages(limit=10)
    for msg in recent_messages:
        reply_text = f" (Reply to: {msg.get('reply_to_message_id', 'N/A')})" if 'reply_to_message_id' in msg else ""
        print(f"   {msg['author']}: {msg['content'][:50]}{'...' if len(msg['content']) > 50 else ''}{reply_text}")

if __name__ == "__main__":
    main()

# Alternative: Interactive function for manual testing
def insert_custom_message():
    """Interactive function to insert a custom message."""
    print("\n🔧 Custom Message Insertion")
    author = input("Enter author name: ").strip()
    content = input("Enter message content: ").strip()
    reply_to = input("Enter message ID to reply to (or press Enter for new message): ").strip()
    
    reply_to_message_id = reply_to if reply_to else None
    
    return insert_message(author, content, reply_to_message_id)

# Uncomment the line below to run interactive mode instead
# insert_custom_message()