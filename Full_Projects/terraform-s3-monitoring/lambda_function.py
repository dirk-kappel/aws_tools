import base64
import gzip
import json
import logging
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

def handler(event, context):
    """
    Process CloudTrail events from CloudWatch Logs
    """
    try:
        # CloudWatch Logs sends compressed data
        log_events = event.get('awslogs', {}).get('data', '')
        
        if log_events:
            # Decode and decompress the log data
            compressed_payload = base64.b64decode(log_events)
            uncompressed_payload = gzip.decompress(compressed_payload)
            log_data = json.loads(uncompressed_payload)
            
            logger.info("CloudWatch Logs Event Data:")
            logger.info(json.dumps(log_data, indent=2, default=str))
            
            # Process each log event
            for log_event in log_data.get('logEvents', []):
                message = log_event.get('message', '')
                
                # Parse CloudTrail event
                if message:
                    try:
                        cloudtrail_event = json.loads(message)
                        
                        # Process each record in the CloudTrail event
                        for record in cloudtrail_event.get('Records', []):
                            if record.get('eventSource') == 's3.amazonaws.com':
                                logger.info("S3 CloudTrail Event:")
                                logger.info(json.dumps(record, indent=2, default=str))
                                
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse CloudTrail message: {message}")
        else:
            # Fallback - log the entire event
            logger.info("Complete CloudWatch Logs Event:")
            logger.info(json.dumps(event, indent=2, default=str))
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'CloudTrail events processed successfully'})
        }
        
    except Exception as e:
        logger.error(f"Error processing CloudTrail events: {str(e)}")
        logger.error(f"Event data: {json.dumps(event, default=str)}")
        
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }