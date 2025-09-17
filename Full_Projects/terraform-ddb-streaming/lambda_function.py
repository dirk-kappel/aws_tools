import json
import logging
from datetime import datetime
from typing import Dict, List, Optional

import boto3

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

# Environment variables (set by Terraform)
import os

TABLE_NAME = os.environ['DYNAMODB_TABLE_NAME']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

# Get DynamoDB table reference
messages_table = dynamodb.Table(TABLE_NAME)

def lambda_handler(event, context):
    """
    Main Lambda handler for processing DynamoDB stream events.
    
    Args:
        event: DynamoDB stream event containing records
        context: Lambda context object
        
    Returns:
        dict: Response with processing results
    """
    logger.info(f"Processing {len(event['Records'])} stream records")
    
    successful_processes = 0
    failed_processes = 0
    
    for record in event['Records']:
        try:
            # Only process INSERT events (new messages)
            if record['eventName'] == 'INSERT':
                process_new_message(record)
                successful_processes += 1
            else:
                logger.info(f"Skipping {record['eventName']} event")
                
        except Exception as e:
            logger.error(f"Error processing record: {str(e)}")
            logger.error(f"Record: {json.dumps(record, default=str)}")
            failed_processes += 1
    
    logger.info(f"Processing complete: {successful_processes} successful, {failed_processes} failed")
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'processed': successful_processes,
            'failed': failed_processes
        })
    }

def process_new_message(record: Dict) -> None:
    """
    Process a new message from DynamoDB stream and send appropriate notification.
    
    Args:
        record: DynamoDB stream record containing the new message data
    """
    # Extract message data from stream record
    message_data = record['dynamodb']['NewImage']
    
    # Convert DynamoDB format to regular Python dict
    message = deserialize_dynamodb_item(message_data)
    
    logger.info(f"Processing message: {message['message_id']} from {message['author']}")
    
    # Check if this is a reply to another message
    is_reply = 'reply_to_message_id' in message and message['reply_to_message_id']
    
    if is_reply:
        # Handle reply message
        original_message = get_original_message(message['reply_to_message_id'])
        send_reply_notification(message, original_message)
    else:
        # Handle new message
        send_new_message_notification(message)

def deserialize_dynamodb_item(dynamodb_item: Dict) -> Dict:
    """
    Convert DynamoDB stream format to regular Python dict.
    
    Args:
        dynamodb_item: DynamoDB item in stream format
        
    Returns:
        dict: Regular Python dictionary
    """
    result = {}
    
    for key, value in dynamodb_item.items():
        if 'S' in value:  # String
            result[key] = value['S']
        elif 'N' in value:  # Number
            result[key] = value['N']
        elif 'BOOL' in value:  # Boolean
            result[key] = value['BOOL']
        elif 'NULL' in value:  # Null
            result[key] = None
        # Add more types as needed
    
    return result

def get_original_message(original_message_id: str) -> Optional[Dict]:
    """
    Retrieve the original message that is being replied to.
    
    Args:
        original_message_id: ID of the original message
        
    Returns:
        dict: Original message data or None if not found
    """
    try:
        response = messages_table.get_item(Key={'message_id': original_message_id})
        
        if 'Item' in response:
            logger.info(f"Found original message: {original_message_id}")
            return response['Item']
        else:
            logger.warning(f"Original message not found: {original_message_id}")
            return None
            
    except Exception as e:
        logger.error(f"Error retrieving original message {original_message_id}: {str(e)}")
        return None

def send_new_message_notification(message: Dict) -> None:
    """
    Send SNS notification for a new message.
    
    Args:
        message: Message data dictionary
    """
    subject = f"📝 New Message from {message['author']}"
    
    body = f"""🔔 New Message Notification

👤 Author: {message['author']}
💬 Content: {message['content']}
🕐 Time: {message['timestamp']}

Message ID: {message['message_id']}
"""
    
    message_attributes = {
        'message_type': {
            'DataType': 'String',
            'StringValue': 'new_message'
        },
        'author': {
            'DataType': 'String',
            'StringValue': message['author']
        },
        'message_id': {
            'DataType': 'String',
            'StringValue': message['message_id']
        }
    }
    
    publish_to_sns(subject, body, message_attributes)

def send_reply_notification(reply_message: Dict, original_message: Optional[Dict]) -> None:
    """
    Send SNS notification for a reply message, including original message context.
    
    Args:
        reply_message: Reply message data
        original_message: Original message being replied to (can be None)
    """
    subject = f"💬 Reply from {reply_message['author']}"
    
    if original_message:
        body = f"""🔔 New Reply Notification

👤 Reply Author: {reply_message['author']}
💬 Reply: {reply_message['content']}
🕐 Reply Time: {reply_message['timestamp']}

📝 Original Message:
👤 Original Author: {original_message['author']}
💬 Original Content: {original_message['content']}
🕐 Original Time: {original_message['timestamp']}

Reply Message ID: {reply_message['message_id']}
Original Message ID: {original_message['message_id']}
"""
    else:
        # Handle case where original message couldn't be found
        body = f"""🔔 New Reply Notification

👤 Reply Author: {reply_message['author']}
💬 Reply: {reply_message['content']}
🕐 Reply Time: {reply_message['timestamp']}

⚠️ Original message could not be retrieved (ID: {reply_message.get('reply_to_message_id', 'Unknown')})

Reply Message ID: {reply_message['message_id']}
"""
    
    message_attributes = {
        'message_type': {
            'DataType': 'String',
            'StringValue': 'reply'
        },
        'reply_author': {
            'DataType': 'String',
            'StringValue': reply_message['author']
        },
        'reply_message_id': {
            'DataType': 'String',
            'StringValue': reply_message['message_id']
        }
    }
    
    if original_message:
        message_attributes['original_author'] = {
            'DataType': 'String',
            'StringValue': original_message['author']
        }
        message_attributes['original_message_id'] = {
            'DataType': 'String',
            'StringValue': original_message['message_id']
        }
    
    publish_to_sns(subject, body, message_attributes)

def publish_to_sns(subject: str, message: str, message_attributes: Dict) -> None:
    """
    Publish a message to the SNS topic.
    
    Args:
        subject: Email subject line
        message: Message body
        message_attributes: SNS message attributes
    """
    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject,
            MessageAttributes=message_attributes
        )
        
        logger.info(f"SNS message published successfully: {response['MessageId']}")
        
    except Exception as e:
        logger.error(f"Failed to publish to SNS: {str(e)}")
        raise  # Re-raise to trigger Lambda retry if needed