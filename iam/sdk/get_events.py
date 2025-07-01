#!/usr/bin/env python3
# get_events.py
"""
CloudTrail events downloader using AWS boto3 SDK.

Downloads CloudTrail events based on lookup attributes and saves them to a JSON file.
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


@dataclass
class SearchParameters:
    """Container for search parameters."""

    attribute_key: str
    attribute_value: str
    start_time: datetime | None = None
    end_time: datetime | None = None
    max_items: str | int = "all"
    output_file: str = "cloudtrail_events.json"


def initialize_cloudtrail_client():
    """Initialize CloudTrail client with error handling."""
    try:
        cloudtrail_client = boto3.client("cloudtrail")
    except NoCredentialsError:
        print("❌ AWS credentials not found. Please configure your credentials.")
        print("   Run 'aws configure' or set environment variables.")
        sys.exit(1)
    else:
        return cloudtrail_client


def parse_datetime(date_string: str) -> datetime | None:
    """Parse datetime string in various formats."""
    if not date_string:
        return None

    # Use pattern matching approach to avoid try-except in loop
    # Check for common patterns first to minimize parsing attempts
    if "T" in date_string and date_string.endswith("Z"):
        try:
            return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    elif "T" in date_string:
        try:
            return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    elif " " in date_string:
        try:
            return datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    elif len(date_string) == 10:  # YYYY-MM-DD format
        try:
            return datetime.strptime(date_string, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    # Create error message as variable first
    error_msg = f"Unable to parse date: {date_string}"
    raise ValueError(error_msg)


def lookup_events(client, search_params: SearchParameters) -> list:
    """
    Lookup CloudTrail events based on specified attributes.

    Args:
        client: CloudTrail boto3 client
        search_params: SearchParameters object containing search criteria

    Returns:
        List of events

    """
    # Set default time range if not provided
    now = datetime.now(timezone.utc)
    start_time = search_params.start_time or (now - timedelta(days=7))
    end_time = search_params.end_time or now

    lookup_attributes = [{
        "AttributeKey": search_params.attribute_key,
        "AttributeValue": search_params.attribute_value,
    }]

    # Convert max_items to number if it's "all"
    max_items_num = float("inf") if search_params.max_items == "all" else int(search_params.max_items)

    all_events = []
    next_token = None

    try:
        while True:
            # Calculate how many items to request this time
            if search_params.max_items == "all":
                items_to_request = 50  # API limit per call
            else:
                items_to_request = min(max_items_num - len(all_events), 50)

            # Prepare the request parameters
            params = {
                "LookupAttributes": lookup_attributes,
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": items_to_request,
            }

            if next_token:
                params["NextToken"] = next_token

            print(f"📡 Fetching events... (Retrieved: {len(all_events)})")
            response = client.lookup_events(**params)

            events = response.get("Events", [])
            all_events.extend(events)

            # Print progress
            for i, event in enumerate(events, len(all_events) - len(events) + 1):
                print(f"  {i}. {event['EventTime'].strftime('%Y-%m-%d %H:%M:%S')} - {event['EventName']} ({event['EventSource']})")

            # Check if we have more events and haven't reached our limit
            next_token = response.get("NextToken")
            if not next_token or (search_params.max_items != "all" and len(all_events) >= max_items_num):
                break

        print(f"✅ Retrieved {len(all_events)} events total")
    except ClientError as e:
        print(f"❌ Error retrieving events: {e.response['Error']['Message']}")
        return []
    else:
        return all_events


def save_events_to_file(events: list, search_params: SearchParameters, output_directory: Path | None = None) -> str | None:
    """
    Save events to a JSON file.

    Args:
        events: List of CloudTrail events
        search_params: SearchParameters object containing search criteria
        output_directory: Directory to save the file (optional)

    Returns:
        Path to saved file or None if failed

    """
    if output_directory:
        output_path = output_directory / search_params.output_file
        output_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        output_path = Path(search_params.output_file)

    # Convert datetime objects to strings and parse CloudTrailEvent JSON
    serializable_events = []
    for event in events:
        event_copy = event.copy()
        if "EventTime" in event_copy:
            event_copy["EventTime"] = event_copy["EventTime"].isoformat()

        # Parse the CloudTrailEvent JSON string into a proper JSON object
        if "CloudTrailEvent" in event_copy and isinstance(event_copy["CloudTrailEvent"], str):
            try:
                event_copy["CloudTrailEvent"] = json.loads(event_copy["CloudTrailEvent"])
            except json.JSONDecodeError as e:
                print(f"⚠️ Warning: Could not parse CloudTrailEvent JSON for event {event_copy.get('EventId', 'unknown')}: {e}")

        serializable_events.append(event_copy)

    try:
        with output_path.open("w", encoding="utf-8") as f:
            json.dump({
                "SearchParameters": {
                    "AttributeKey": search_params.attribute_key,
                    "AttributeValue": search_params.attribute_value,
                    "StartTime": search_params.start_time.isoformat() if search_params.start_time else None,
                    "EndTime": search_params.end_time.isoformat() if search_params.end_time else None,
                },
                "Summary": {
                    "TotalEvents": len(serializable_events),
                    "RetrievedAt": datetime.now(timezone.utc).isoformat(),
                },
                "Events": serializable_events,
            }, f, indent=2, default=str)

        print(f"💾 Events saved to: {output_path}")
    except (OSError, json.JSONEncodeError) as e:
        print(f"❌ Error saving events to file: {e}")
        return None
    else:
        return str(output_path)


def get_attribute_choice() -> tuple[str, str]:
    """Get attribute key and value from user."""
    attribute_keys = [
        "Username",
        "AccessKeyId",
        "EventId",
        "EventName",
        "ReadOnly",
        "ResourceType",
        "ResourceName",
        "EventSource",
    ]

    print("=" * 60)
    print("🔍 CLOUDTRAIL EVENT LOOKUP")
    print("=" * 60)
    print("Choose lookup attribute:")
    for i, choice in enumerate(attribute_keys, start=1):
        print(f"  {i}. {choice}")

    while True:
        try:
            choice = int(input("\nEnter your choice (1-8): ").strip())
            if 1 <= choice <= len(attribute_keys):
                attribute_key = attribute_keys[choice - 1]
                break
            print("❌ Invalid choice. Please enter a number between 1 and 8.")
        except ValueError:
            print("❌ Invalid input. Please enter a number.")

    attribute_value = input(f"Enter the value for {attribute_key}: ").strip()
    return attribute_key, attribute_value


def get_time_range() -> tuple[datetime | None, datetime | None]:
    """Get time range from user."""
    print("\n📅 Time Range Options:")
    print("  1. Last X days (default)")
    print("  2. Last 90 days")
    print("  3. Custom absolute time range")

    time_choice = input("Choose time range option (1-3) [default: 1]: ").strip()
    if not time_choice:
        time_choice = "1"

    now = datetime.now(timezone.utc)

    if time_choice == "1":
        days_str = input("Enter number of days to look back [default: 7]: ").strip()
        days = int(days_str) if days_str else 7
        start_time = now - timedelta(days=days)
        end_time = now
        print(f"  📅 Searching last {days} days")
        return start_time, end_time

    if time_choice == "2":
        start_time = now - timedelta(days=90)
        end_time = now
        print("  📅 Searching last 90 days")
        return start_time, end_time

    if time_choice == "3":
        print("  📅 Enter custom time range:")
        start_time_str = input("    Start time (YYYY-MM-DD HH:MM:SS or YYYY-MM-DD): ").strip()
        end_time_str = input("    End time (YYYY-MM-DD HH:MM:SS or YYYY-MM-DD): ").strip()

        start_time = None
        end_time = None

        if start_time_str:
            try:
                start_time = parse_datetime(start_time_str)
            except ValueError as e:
                print(f"❌ Error parsing start time: {e}")
                sys.exit(1)

        if end_time_str:
            try:
                end_time = parse_datetime(end_time_str)
            except ValueError as e:
                print(f"❌ Error parsing end time: {e}")
                sys.exit(1)

        return start_time, end_time

    # Default case
    print("❌ Invalid choice, using default (last 7 days)")
    start_time = now - timedelta(days=7)
    end_time = now
    return start_time, end_time


def get_max_items_and_filename() -> tuple[str | int, str]:
    """Get max items and output filename from user."""
    # Max items selection
    max_items_str = input("\n🔢 Maximum events to retrieve (enter number or 'all') [default: all]: ").strip()
    if not max_items_str or max_items_str.lower() == "all":
        max_items = "all"
    else:
        try:
            max_items = int(max_items_str)
        except ValueError:
            print("❌ Invalid number, using 'all'")
            max_items = "all"

    output_file = input("📁 Output filename [default: cloudtrail_events.json]: ").strip()
    if not output_file:
        output_file = "cloudtrail_events.json"

    return max_items, output_file


def choose_lookup_attribute() -> SearchParameters:
    """Interactive menu for choosing lookup attributes."""
    attribute_key, attribute_value = get_attribute_choice()
    start_time, end_time = get_time_range()
    max_items, output_file = get_max_items_and_filename()

    print("=" * 60)
    return SearchParameters(
        attribute_key=attribute_key,
        attribute_value=attribute_value,
        start_time=start_time,
        end_time=end_time,
        max_items=max_items,
        output_file=output_file,
    )


def main():
    """Main function to orchestrate the CloudTrail event lookup and download."""
    print("🚀 CloudTrail Events Downloader")

    # Get user input
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

    # Lookup events
    events = lookup_events(client, search_params)

    if events:
        # Save events to file using secure temporary directory
        output_directory = Path(tempfile.gettempdir()) / "cloudtrail_downloads"
        saved_file = save_events_to_file(events, search_params, output_directory)

        if saved_file:
            print(f"\n✨ Successfully downloaded {len(events)} CloudTrail events!")
            print(f"📁 File location: {saved_file}")
        else:
            print("\n❌ Failed to save events to file.")
    else:
        print("\n❌ No events found or failed to retrieve events.")


if __name__ == "__main__":
    main()
