#!/usr/bin/env python3
# get_unique_events.py
"""
CloudTrail events analyzer that uses the get_events module.

Analyzes CloudTrail events to extract unique API calls and their parameters.
Can download events using get_events module or process existing JSON files.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Import from our get_events module
from get_events import (
    choose_lookup_attribute,
    initialize_cloudtrail_client,
    lookup_events,
    save_events_to_file,
)


@dataclass
class APICallInfo:
    """Container for API call information."""

    service: str
    event_name: str
    resource_arns: set[str]
    resource_names: set[str]
    resource_types: set[str]
    request_parameters: set[str]
    count: int = 0

    def __post_init__(self):
        """Initialize sets if they're not already sets."""
        if not isinstance(self.resource_arns, set):
            self.resource_arns = set(self.resource_arns) if self.resource_arns else set()
        if not isinstance(self.resource_names, set):
            self.resource_names = set(self.resource_names) if self.resource_names else set()
        if not isinstance(self.resource_types, set):
            self.resource_types = set(self.resource_types) if self.resource_types else set()
        if not isinstance(self.request_parameters, set):
            self.request_parameters = set(self.request_parameters) if self.request_parameters else set()


def extract_resource_info(record: dict) -> tuple[set[str], set[str], set[str], set[str]]:
    """
    Extract resource information from a CloudTrail record.

    Args:
        record: CloudTrail event record

    Returns:
        Tuple of (resource_arns, resource_names, resource_types, request_parameters)

    """
    resource_arns = set()
    resource_names = set()
    resource_types = set()
    request_parameters = set()

    # Extract from Resources field
    if "resources" in record:
        for resource in record["resources"]:
            if "ARN" in resource:
                resource_arns.add(resource["ARN"])
            if "type" in resource:
                resource_types.add(resource["type"])

    # Extract from requestParameters
    if record.get("requestParameters"):
        request_params = record["requestParameters"]

        # Common parameter names that contain resource identifiers
        resource_param_keys = [
            "bucketName", "key", "keyName",
            "instanceId", "instanceIds", "instanceType",
            "groupName", "groupId", "securityGroupIds",
            "vpcId", "subnetId", "subnetIds",
            "roleName", "policyName", "userName",
            "functionName", "tableName", "topicArn",
            "queueUrl", "queueName", "clusterName",
            "dbInstanceIdentifier", "dbClusterIdentifier",
            "loadBalancerName", "targetGroupArn",
            "restApiId", "stackName", "resourceType",
            "repository", "imageId", "taskDefinition",
            "workspaceId", "directoryId", "certificateArn",
            "keyId", "aliasName", "secretName",
            "pipelineName", "projectName", "buildId",
            "distributionId", "hostedZoneId", "recordName",
            "streamName", "deliveryStreamName", "ruleName",
        ]

        def process_param_value(key: str, value) -> None:
            """Process a parameter value and add to sets."""
            if not value:
                return

            if isinstance(value, list):
                for item in value:
                    if item:
                        request_parameters.add(f"{key}={item}")
                        resource_names.add(str(item))
            elif isinstance(value, dict):
                # Handle nested dictionaries
                for nested_key, nested_value in value.items():
                    if nested_value and nested_key in resource_param_keys:
                        request_parameters.add(f"{key}.{nested_key}={nested_value}")
                        resource_names.add(str(nested_value))
            else:
                request_parameters.add(f"{key}={value}")
                resource_names.add(str(value))

        for key, value in request_params.items():
            # Add key-value pairs for important parameters
            if key in resource_param_keys or (key.endswith(("Name", "Id", "Arn", "Uri", "Url")) and value):
                process_param_value(key, value)

    # Extract from responseElements
    if record.get("responseElements"):
        response_elements = record["responseElements"]

        def extract_from_response(obj, prefix=""):
            """Recursively extract resource identifiers from response elements."""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_key = f"{prefix}.{key}" if prefix else key
                    if key.endswith(("Arn", "Id")) and isinstance(value, str) and value:
                        resource_arns.add(value)
                    elif isinstance(value, dict):
                        extract_from_response(value, current_key)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                extract_from_response(item, current_key)

        extract_from_response(response_elements)

    # Extract additional info from top-level fields
    if "userIdentity" in record and "arn" in record["userIdentity"]:
        resource_arns.add(record["userIdentity"]["arn"])

    if "sourceIPAddress" in record:
        request_parameters.add(f"sourceIPAddress={record['sourceIPAddress']}")

    return resource_arns, resource_names, resource_types, request_parameters


def analyze_cloudtrail_events(events: list) -> dict[str, APICallInfo]:
    """
    Analyze CloudTrail events to extract unique API calls and their parameters.

    Args:
        events: List of CloudTrail events

    Returns:
        Dictionary mapping API call names to APICallInfo objects

    """
    api_calls = defaultdict(lambda: APICallInfo("", "", set(), set(), set(), set(), 0))

    for event in events:
        # Handle both direct CloudTrail API events and parsed JSON file events
        record = event.get("CloudTrailEvent", event)

        # If CloudTrailEvent is a JSON string, parse it
        if isinstance(record, str):
            try:
                record = json.loads(record)
            except json.JSONDecodeError as e:
                print(f"⚠️ Warning: Could not parse CloudTrailEvent JSON: {e}")
                continue

        # Skip if record is still not a dictionary
        if not isinstance(record, dict):
            print(f"⚠️ Warning: Unexpected record type: {type(record)}")
            continue

        if "eventSource" in record and "eventName" in record:
            # Extract service name and event name
            service = record["eventSource"].split(".")[0]
            event_name = record["eventName"]
            api_call_key = f"{service}:{event_name}"

            # Extract resource information
            resource_arns, resource_names, resource_types, request_parameters = extract_resource_info(record)

            # Update or create API call info
            if api_call_key in api_calls:
                api_call_info = api_calls[api_call_key]
                api_call_info.resource_arns.update(resource_arns)
                api_call_info.resource_names.update(resource_names)
                api_call_info.resource_types.update(resource_types)
                api_call_info.request_parameters.update(request_parameters)
                api_call_info.count += 1
            else:
                api_calls[api_call_key] = APICallInfo(
                    service=service,
                    event_name=event_name,
                    resource_arns=resource_arns,
                    resource_names=resource_names,
                    resource_types=resource_types,
                    request_parameters=request_parameters,
                    count=1,
                )

    return dict(api_calls)


def process_json_file(file_path: Path) -> dict[str, APICallInfo]:
    """
    Process a JSON file containing CloudTrail records.

    Args:
        file_path: Path to the JSON file

    Returns:
        Dictionary of API call information

    """
    try:
        with file_path.open() as f:
            data = json.load(f)

            events = []

            # Handle different JSON structures
            if "Records" in data:
                # Original CloudTrail log format
                events = data["Records"]
                print(f"  📝 Found {len(events)} records in CloudTrail format")
            elif "Events" in data:
                # Our new format from the get_events downloader
                events = data["Events"]
                print(f"  📝 Found {len(events)} events in get_events format")
            else:
                print(f"  ⚠️ Unknown JSON format in {file_path}")
                return {}

            return analyze_cloudtrail_events(events)

    except FileNotFoundError:
        print(f"  ❌ File not found: {file_path}")
        return {}
    except json.JSONDecodeError as e:
        print(f"  ❌ JSON decode error in {file_path}: {e}")
        return {}
    except Exception as e:
        print(f"  ❌ Error processing {file_path}: {e}")
        return {}


def print_analysis_results(api_calls: dict[str, APICallInfo]):
    """
    Print the analysis results in a formatted way.

    Args:
        api_calls: Dictionary of API call information

    """
    print(f"\n{'='*80}")
    print("📊 CLOUDTRAIL ANALYSIS RESULTS")
    print(f"{'='*80}")
    print(f"Total unique API calls: {len(api_calls)}")
    print()

    # Sort by service first, then by event name
    sorted_calls = sorted(api_calls.items(), key=lambda x: (x[1].service, x[1].event_name))

    for api_call, info in sorted_calls:
        print(f"🔹 {api_call} (called {info.count} times)")

        if info.resource_types:
            print(f"   📋 Resource Types: {', '.join(sorted(info.resource_types))}")

        if info.resource_arns:
            print("   🏷️  Resource ARNs:")
            for arn in sorted(info.resource_arns)[:5]:  # Limit to first 5
                print(f"      • {arn}")
            if len(info.resource_arns) > 5:
                print(f"      ... and {len(info.resource_arns) - 5} more ARNs")

        if info.resource_names:
            resource_names_limited = sorted(info.resource_names)[:10]  # Limit to first 10
            print(f"   📝 Resource Names: {', '.join(resource_names_limited)}")
            if len(info.resource_names) > 10:
                print(f"      ... and {len(info.resource_names) - 10} more")

        if info.request_parameters:
            params_limited = sorted(info.request_parameters)[:5]  # Limit to first 5
            print(f"   ⚙️  Key Parameters: {', '.join(params_limited)}")
            if len(info.request_parameters) > 5:
                print(f"      ... and {len(info.request_parameters) - 5} more")

        print()


def save_analysis_to_file(api_calls: dict[str, APICallInfo], filename: str) -> bool:
    """
    Save analysis results to a JSON file.

    Args:
        api_calls: Dictionary of API call information
        filename: Output filename

    Returns:
        True if successful, False otherwise

    """
    try:
        # Convert APICallInfo objects to dictionaries for JSON serialization
        analysis_data = {}
        for api_call, info in api_calls.items():
            analysis_data[api_call] = {
                "service": info.service,
                "event_name": info.event_name,
                "count": info.count,
                "resource_arns": sorted(info.resource_arns),
                "resource_names": sorted(info.resource_names),
                "resource_types": sorted(info.resource_types),
                "request_parameters": sorted(info.request_parameters),
            }

        with Path(filename).open("w", encoding="utf-8") as f:
            json.dump({
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                "total_unique_api_calls": len(api_calls),
                "api_calls": analysis_data,
            }, f, indent=2)


    except Exception as e:
        print(f"❌ Error saving analysis: {e}")
        return False

    else:
        print(f"✅ Analysis saved to: {filename}")
        return True


def download_and_analyze_events() -> dict[str, APICallInfo]:
    """Download events from CloudTrail API and analyze them."""
    print("📥 DOWNLOAD MODE: Getting events from AWS CloudTrail API")
    print("=" * 60)

    # Get search parameters using the get_events module
    search_params = choose_lookup_attribute()

    # Initialize CloudTrail client
    client = initialize_cloudtrail_client()

    # Display search parameters
    print("\n🔎 Searching for events:")
    print(f"   Attribute: {search_params.attribute_key} = '{search_params.attribute_value}'")
    print(f"   Start time: {search_params.start_time.strftime('%Y-%m-%d %H:%M:%S') if search_params.start_time else 'Not specified'}")
    print(f"   End time: {search_params.end_time.strftime('%Y-%m-%d %H:%M:%S') if search_params.end_time else 'Not specified'}")
    print(f"   Max events: {search_params.max_items}")
    print()

    # Lookup events using the get_events module
    events = lookup_events(client, search_params)

    if not events:
        print("\n❌ No events found or failed to retrieve events.")
        return {}

    # Debug: Print sample event structure
    if events:
        print("\n🔍 Sample event structure:")
        sample_event = events[0]
        print(f"   Event keys: {list(sample_event.keys())}")
        if "CloudTrailEvent" in sample_event:
            print(f"   CloudTrailEvent type: {type(sample_event['CloudTrailEvent'])}")
            if isinstance(sample_event["CloudTrailEvent"], str):
                print("   CloudTrailEvent is a JSON string (will be parsed)")
            else:
                print("   CloudTrailEvent is already parsed")

    # Optionally save events to file
    save_events = input(f"\n💾 Save {len(events)} events to file? (y/n) [default: y]: ").strip().lower()
    if save_events in ["", "y", "yes"]:
        import tempfile
        output_directory = Path(tempfile.gettempdir()) / "cloudtrail_downloads"
        saved_file = save_events_to_file(events, search_params, output_directory)

        if saved_file:
            print(f"📁 Events saved to: {saved_file}")

    # Analyze the downloaded events
    print(f"\n🔍 Analyzing {len(events)} events...")
    return analyze_cloudtrail_events(events)


def analyze_existing_files() -> dict[str, APICallInfo]:
    """Analyze existing JSON files containing CloudTrail events."""
    print("📂 ANALYZE MODE: Processing existing JSON files")
    print("=" * 60)

    # Get directory and files
    directory_input = input("Enter directory path [default: current directory]: ").strip()
    directory = Path(directory_input) if directory_input else Path.cwd()

    if not directory.exists():
        print(f"❌ Directory does not exist: {directory}")
        return {}

    json_files_input = input("Enter JSON file names (comma-separated) [default: *.json]: ").strip()
    if json_files_input:
        json_files = [directory / f.strip() for f in json_files_input.split(",")]
        # Filter to only existing files
        json_files = [f for f in json_files if f.exists()]
    else:
        json_files = list(directory.glob("*.json"))

    if not json_files:
        print(f"❌ No JSON files found in: {directory}")
        return {}

    print(f"\n📂 Processing {len(json_files)} files in: {directory}")

    all_api_calls = {}
    for file_path in json_files:
        print(f"\n📄 Processing: {file_path.name}")
        file_api_calls = process_json_file(file_path)

        # Merge results
        for api_call, info in file_api_calls.items():
            if api_call in all_api_calls:
                existing_info = all_api_calls[api_call]
                existing_info.resource_arns.update(info.resource_arns)
                existing_info.resource_names.update(info.resource_names)
                existing_info.resource_types.update(info.resource_types)
                existing_info.request_parameters.update(info.request_parameters)
                existing_info.count += info.count
            else:
                all_api_calls[api_call] = info

    return all_api_calls


def main():
    """Main function to orchestrate the CloudTrail event analysis."""
    print("🚀 CloudTrail Events Analyzer")
    print("=" * 60)
    print("Choose operation mode:")
    print("  1. Download and analyze events from AWS CloudTrail API")
    print("  2. Analyze existing JSON files")

    mode = input("\nEnter your choice (1-2): ").strip()

    if mode == "1":
        api_calls = download_and_analyze_events()
    elif mode == "2":
        api_calls = analyze_existing_files()
    else:
        print("❌ Invalid choice. Exiting.")
        return

    # Print analysis results
    if api_calls:
        print_analysis_results(api_calls)

        # Optionally save analysis to file
        save_analysis = input("\n💾 Save analysis to file? (y/n) [default: n]: ").strip().lower()
        if save_analysis in ["y", "yes"]:
            analysis_file = input("Enter filename [default: cloudtrail_analysis.json]: ").strip()
            if not analysis_file:
                analysis_file = "cloudtrail_analysis.json"

            save_analysis_to_file(api_calls, analysis_file)

        # Print summary
        total_calls = sum(info.count for info in api_calls.values())
        unique_services = len({info.service for info in api_calls.values()})
        print("\n📈 SUMMARY:")
        print(f"   • {len(api_calls)} unique API calls")
        print(f"   • {total_calls} total API calls")
        print(f"   • {unique_services} AWS services used")

    else:
        print("\n❌ No API calls found to analyze.")


if __name__ == "__main__":
    main()
