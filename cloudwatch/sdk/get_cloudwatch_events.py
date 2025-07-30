#!/usr/bin/env python3
"""
Simple CloudWatch Logs Downloader.

Downloads log events from multiple log streams within a single AWS CloudWatch log group.
Saves logs to console output and optionally to a structured JSON or text file.
JSON format is compatible with CloudTrail analysis tools for searchable log analysis.
"""

import json
from datetime import datetime, timedelta

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Configuration - Modify these settings as needed
LOG_GROUP_NAME = "aws-cloudtrail-logs-620794384249-c006cf13"  # Log group name
LOG_STREAM_NAMES = [
    "620794384249_CloudTrail_us-gov-west-1",
    "620794384249_CloudTrail_us-gov-west-1_2",
    "620794384249_CloudTrail_us-gov-west-1_3",
    "620794384249_CloudTrail_us-gov-west-1_4",
]  # List of specific log stream names (empty list for all streams)
FILTER_PATTERN = "dirk.effectual"  # Filter pattern (empty string for no filter)
DAYS_BACK = 321  # How many days back to search
AWS_REGION = "us-gov-west-1"  # AWS region
OUTPUT_FILE = "cloudwatch_logs.json"  # Output file name (set to None to disable file output)
OUTPUT_FORMAT = "json"  # Output format: "text" or "json"

def download_cloudwatch_logs():
    """Download and display CloudWatch log events from specific log streams."""
    
    # Calculate time range (in milliseconds since epoch)
    end_time = datetime.now()
    start_time = end_time - timedelta(days=DAYS_BACK)
    
    start_time_ms = int(start_time.timestamp() * 1000)
    end_time_ms = int(end_time.timestamp() * 1000)
    
    try:
        # Create CloudWatch Logs client
        client = boto3.client('logs', region_name=AWS_REGION)
        
        print(f"Downloading logs from: {LOG_GROUP_NAME}")
        if LOG_STREAM_NAMES:
            print(f"Specific log streams: {len(LOG_STREAM_NAMES)} stream(s)")
        else:
            print("All log streams in the group")
        print(f"Time range: {start_time} to {end_time} ({DAYS_BACK} day(s) back)")
        print(f"Filter pattern: '{FILTER_PATTERN}'" if FILTER_PATTERN else "No filter applied")
        if OUTPUT_FILE:
            print(f"Output file: {OUTPUT_FILE} (format: {OUTPUT_FORMAT})")
        print("-" * 80)
        
        # Prepare the filter parameters
        filter_params = {
            'logGroupName': LOG_GROUP_NAME,
            'startTime': start_time_ms,
            'endTime': end_time_ms,
        }
        
        # Add specific log streams if specified
        if LOG_STREAM_NAMES:
            filter_params['logStreamNames'] = LOG_STREAM_NAMES
        
        # Add filter pattern if specified
        if FILTER_PATTERN:
            filter_params['filterPattern'] = FILTER_PATTERN
        
        total_event_count = 0
        events_data = []  # Store events for JSON output
        
        # Open output file if specified
        output_file = None
        if OUTPUT_FILE and OUTPUT_FORMAT == "text":
            output_file = open(OUTPUT_FILE, 'w', encoding='utf-8')
            # Write header to file
            output_file.write(f"CloudWatch Logs Export\n")
            output_file.write(f"Log Group: {LOG_GROUP_NAME}\n")
            if LOG_STREAM_NAMES:
                output_file.write(f"Log Streams: {len(LOG_STREAM_NAMES)} specific stream(s)\n")
                for stream in LOG_STREAM_NAMES:
                    output_file.write(f"  - {stream}\n")
            else:
                output_file.write(f"Log Streams: All streams in the group\n")
            output_file.write(f"Time range: {start_time} to {end_time} ({DAYS_BACK} day(s) back)\n")
            output_file.write(f"Filter pattern: '{FILTER_PATTERN}'\n" if FILTER_PATTERN else "No filter applied\n")
            output_file.write("=" * 80 + "\n\n")
        
        try:
            # Get log events using paginator for handling large result sets
            paginator = client.get_paginator('filter_log_events')
            page_iterator = paginator.paginate(**filter_params)
            
            # Track events per stream for summary
            stream_counts = {}
            
            # Process each page of results
            for page in page_iterator:
                for event in page.get('events', []):
                    total_event_count += 1
                    timestamp = datetime.fromtimestamp(event['timestamp'] / 1000)
                    log_stream = event.get('logStreamName', 'unknown')
                    message = event['message'].strip()
                    
                    # Count events per stream
                    stream_counts[log_stream] = stream_counts.get(log_stream, 0) + 1
                    
                    log_line = f"[{timestamp}] [{log_stream}] {message}"
                    
                    # Print to console
                    print(log_line)
                    
                    # Handle different output formats
                    if OUTPUT_FILE:
                        if OUTPUT_FORMAT == "json":
                            # Try to parse the message as CloudTrail JSON
                            try:
                                cloudtrail_event = json.loads(message)
                                
                                # Verify this is a CloudTrail event with required fields
                                if all(key in cloudtrail_event for key in ['eventSource', 'eventName', 'eventTime']):
                                    # Use the actual CloudTrail event data
                                    event_data = cloudtrail_event.copy()
                                    
                                    # Add some metadata about where this came from
                                    event_data['_metadata'] = {
                                        'sourceLogGroup': LOG_GROUP_NAME,
                                        'sourceLogStream': log_stream,
                                        'cloudwatchTimestamp': event['timestamp'],
                                        'cloudwatchIngestionTime': event.get('ingestionTime')
                                    }
                                    
                                    events_data.append(event_data)
                                else:
                                    # Not a proper CloudTrail event, skip it
                                    print(f"  ⚠️ Skipping non-CloudTrail message in {log_stream}")
                                    continue
                                    
                            except json.JSONDecodeError:
                                # Message is not valid JSON, create a generic log event
                                print(f"  ⚠️ Non-JSON message in {log_stream}, creating generic event")
                                event_data = {
                                    "eventId": f"cloudwatch-{event.get('eventId', total_event_count)}",
                                    "eventTime": timestamp.isoformat(),
                                    "eventSource": "cloudwatch.amazonaws.com",
                                    "eventName": "LogEvent",
                                    "awsRegion": AWS_REGION,
                                    "sourceIPAddress": "cloudwatch.amazonaws.com",
                                    "userAgent": "CloudWatch Logs",
                                    "logGroup": LOG_GROUP_NAME,
                                    "logStream": log_stream,
                                    "timestamp": event['timestamp'],
                                    "message": message,
                                    "ingestionTime": event.get('ingestionTime'),
                                    "requestParameters": {
                                        "logGroupName": LOG_GROUP_NAME,
                                        "logStreamName": log_stream,
                                        "filterPattern": FILTER_PATTERN if FILTER_PATTERN else None
                                    },
                                    "responseElements": None,
                                    "resources": [
                                        {
                                            "ARN": f"arn:aws:logs:{AWS_REGION}:*:log-group:{LOG_GROUP_NAME}:log-stream:{log_stream}",
                                            "type": "AWS::Logs::LogStream"
                                        }
                                    ],
                                    "serviceEventDetails": {
                                        "logLevel": "INFO",
                                        "messageLength": len(message)
                                    }
                                }
                                
                                # Try to extract log level from message
                                message_upper = message.upper()
                                for level in ["ERROR", "WARN", "WARNING", "INFO", "DEBUG", "TRACE"]:
                                    if level in message_upper:
                                        event_data["serviceEventDetails"]["logLevel"] = level
                                        break
                                
                                events_data.append(event_data)
                        else:
                            # Write to text file
                            output_file.write(log_line + "\n")
        
        finally:
            # Close the text output file or write JSON file
            if output_file:
                output_file.close()
            
            # Write JSON file if specified
            if OUTPUT_FILE and OUTPUT_FORMAT == "json" and events_data:
                json_output = {
                    "exportInfo": {
                        "logGroup": LOG_GROUP_NAME,
                        "logStreams": LOG_STREAM_NAMES if LOG_STREAM_NAMES else "all",
                        "filterPattern": FILTER_PATTERN,
                        "timeRange": {
                            "startTime": start_time.isoformat(),
                            "endTime": end_time.isoformat(),
                            "daysBack": DAYS_BACK
                        },
                        "region": AWS_REGION,
                        "exportTimestamp": datetime.now().isoformat(),
                        "totalEvents": len(events_data)
                    },
                    "Events": events_data
                }
                
                try:
                    with open(OUTPUT_FILE, 'w', encoding='utf-8') as json_file:
                        json.dump(json_output, json_file, indent=2, default=str)
                except Exception as e:
                    print(f"Error writing JSON file: {e}")
        
        print("\n" + "=" * 80)
        print(f"SUMMARY:")
        print(f"Total events found: {total_event_count}")
        
        # Show breakdown by stream
        if stream_counts:
            print(f"Events by log stream:")
            for stream, count in sorted(stream_counts.items()):
                print(f"  {stream}: {count} events")
        
        if total_event_count == 0:
            print("No log events found matching the criteria.")
            print("Try adjusting the log group name, log streams, filter pattern, or time range.")
        elif OUTPUT_FILE:
            if OUTPUT_FORMAT == "json":
                print(f"All logs saved as structured JSON to: {OUTPUT_FILE}")
                print("💡 This JSON file can be analyzed with CloudTrail analysis tools")
            else:
                print(f"All logs compiled and saved to: {OUTPUT_FILE}")
    
    except NoCredentialsError:
        print("Error: AWS credentials not found.")
        print("Please configure your AWS credentials using:")
        print("- AWS CLI: aws configure")
        print("- Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
        print("- IAM roles (if running on EC2)")
    
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'ResourceNotFoundException':
            print(f"Error: Log group '{LOG_GROUP_NAME}' not found.")
            print("Please check the log group name and ensure it exists in the specified region.")
        elif error_code == 'AccessDeniedException':
            print("Error: Access denied.")
            print("Please ensure your AWS credentials have the necessary CloudWatch Logs permissions:")
            print("- logs:FilterLogEvents")
            print("- logs:DescribeLogGroups")
        else:
            print(f"AWS Error ({error_code}): {error_message}")
    
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print("This may be due to network issues, invalid configuration, or insufficient permissions.")

def main():
    """Main function to run the multi-log-stream downloader with structured output."""
    print("CloudWatch Logs Downloader - Searchable Output")
    print("=" * 50)
    download_cloudwatch_logs()

if __name__ == "__main__":
    main()