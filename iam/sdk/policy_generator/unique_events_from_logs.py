#!/usr/bin/env python3
# analyze_user_activity.py
"""
CloudTrail User Activity Analyzer.

Analyzes CloudTrail logs to find all API calls made by a specific user or access key.
Extracts unique API calls and resources for least privilege policy generation.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Constants
ARN_PARTS_MIN_LENGTH = 6  # Minimum parts in an ARN
ROLE_ARN_PARTS_MIN_LENGTH = 2  # Minimum parts in role ARN
MAX_RESOURCES_DISPLAY = 5  # Maximum resources to display in output
MAX_RESOURCE_TYPES_DISPLAY = 5  # Maximum resource types to display
MAX_SOURCE_IPS_DISPLAY = 3  # Maximum source IPs to display
MAX_ACTIONS_DISPLAY = 10  # Maximum actions to display in summary
MAX_SUMMARY_RESOURCES_DISPLAY = 5  # Maximum resources in summary


@dataclass
class UserActivity:
    """Container for user activity information."""

    user_identifier: str
    user_type: str  # 'username', 'access_key', 'role', 'service'
    service: str
    event_name: str
    event_source: str
    resources: set[str]
    resource_types: set[str]
    actions: set[str]  # service:action format
    request_parameters: dict
    conditions: set[str]  # For policy conditions
    source_ips: set[str]
    user_agents: set[str]
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def __post_init__(self):
        """Initialize sets if they're not already sets."""
        if not isinstance(self.resources, set):
            self.resources = set(self.resources) if self.resources else set()
        if not isinstance(self.resource_types, set):
            self.resource_types = set(self.resource_types) if self.resource_types else set()
        if not isinstance(self.actions, set):
            self.actions = set(self.actions) if self.actions else set()
        if not isinstance(self.conditions, set):
            self.conditions = set(self.conditions) if self.conditions else set()
        if not isinstance(self.source_ips, set):
            self.source_ips = set(self.source_ips) if self.source_ips else set()
        if not isinstance(self.user_agents, set):
            self.user_agents = set(self.user_agents) if self.user_agents else set()


@dataclass
class UserSearchCriteria:
    """Search criteria for finding user activity."""

    search_type: str  # 'username', 'access_key', 'role_name', 'user_arn'
    search_value: str
    case_sensitive: bool = False


def get_user_search_criteria() -> UserSearchCriteria:
    """
    Get search criteria from user input.

    Returns:
        UserSearchCriteria object

    """
    print("\n🔍 USER SEARCH CRITERIA")
    print("=" * 40)
    print("What do you want to search for?")
    print("  1. Username (e.g., 'john.doe')")
    print("  2. Access Key ID (e.g., 'AKIA...')")
    print("  3. Role name (e.g., 'MyRole')")
    print("  4. User ARN (e.g., 'arn:aws:iam::123456789012:user/john.doe')")

    while True:
        choice = input("\nEnter your choice (1-4): ").strip()

        if choice == "1":
            search_type = "username"
            prompt = "Enter username to search for: "
            break
        if choice == "2":
            search_type = "access_key"
            prompt = "Enter Access Key ID to search for: "
            break
        if choice == "3":
            search_type = "role_name"
            prompt = "Enter role name to search for: "
            break
        if choice == "4":
            search_type = "user_arn"
            prompt = "Enter user ARN to search for: "
            break
        print("❌ Invalid choice. Please enter 1-4.")
        continue

    search_value = input(prompt).strip()
    if not search_value:
        print("❌ Search value cannot be empty.")
        return get_user_search_criteria()

    case_sensitive = input("Case sensitive search? (y/n) [default: n]: ").strip().lower() in ["y", "yes"]

    return UserSearchCriteria(
        search_type=search_type,
        search_value=search_value,
        case_sensitive=case_sensitive,
    )


def _check_username_match(user_identity: dict, compare_func) -> bool:
    """Check if username matches search criteria."""
    username_fields = ["userName", "name"]
    for field in username_fields:
        if field in user_identity and compare_func(user_identity[field]):
            return True

    # Also check if it's in the ARN
    return "arn" in user_identity and compare_func(user_identity["arn"])


def _check_access_key_match(user_identity: dict, compare_func) -> bool:
    """Check if access key matches search criteria."""
    return "accessKeyId" in user_identity and compare_func(user_identity["accessKeyId"])


def _check_role_name_match(user_identity: dict, compare_func) -> bool:
    """Check if role name matches search criteria."""
    # Check role name in ARN or direct role name
    if "arn" in user_identity and "role/" in user_identity["arn"]:
        role_name = user_identity["arn"].split("role/")[-1].split("/")[0]
        if compare_func(role_name):
            return True

    if user_identity.get("type") == "AssumedRole":
        session_name = user_identity.get("arn", "").split("/")[-1]
        if compare_func(session_name):
            return True

    return False


def _check_user_arn_match(user_identity: dict, compare_func) -> bool:
    """Check if user ARN matches search criteria."""
    return "arn" in user_identity and compare_func(user_identity["arn"])


def matches_user_criteria(record: dict, criteria: UserSearchCriteria) -> bool:
    """
    Check if a CloudTrail record matches the user search criteria.

    Args:
        record: CloudTrail event record
        criteria: Search criteria

    Returns:
        True if record matches criteria

    """
    if "userIdentity" not in record:
        return False

    user_identity = record["userIdentity"]
    search_value = criteria.search_value if criteria.case_sensitive else criteria.search_value.lower()

    def compare_value(field_value: str) -> bool:
        """Compare field value with search criteria."""
        if not field_value:
            return False
        compare_val = field_value if criteria.case_sensitive else field_value.lower()
        return search_value in compare_val

    # Dispatch to appropriate checker based on search type
    matchers = {
        "username": _check_username_match,
        "access_key": _check_access_key_match,
        "role_name": _check_role_name_match,
        "user_arn": _check_user_arn_match,
    }

    matcher = matchers.get(criteria.search_type)
    if matcher:
        return matcher(user_identity, compare_value)

    return False


def _extract_iam_user_info(user_identity: dict) -> tuple[str, str]:
    """Extract IAM user information."""
    return user_identity.get("userName", "unknown"), "username"


def _extract_assumed_role_info(user_identity: dict) -> tuple[str, str]:
    """Extract assumed role information."""
    arn = user_identity.get("arn", "")
    if arn:
        # Extract role name from ARN like arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
        parts = arn.split("/")
        if len(parts) >= ROLE_ARN_PARTS_MIN_LENGTH:
            return parts[-2], "role"  # Role name
    return user_identity.get("principalId", "unknown"), "role"


def _extract_root_user_info(user_identity: dict) -> tuple[str, str]:
    """Extract root user information."""
    return "root", "root"


def _extract_federated_user_info(user_identity: dict, user_type: str) -> tuple[str, str]:
    """Extract federated user information."""
    return user_identity.get("userName", user_identity.get("principalId", "unknown")), user_type


def _extract_access_key_user_info(user_identity: dict) -> tuple[str, str]:
    """Extract access key user information."""
    return user_identity["accessKeyId"], "access_key"


def _extract_default_user_info(user_identity: dict, user_type: str) -> tuple[str, str]:
    """Extract default user information."""
    return user_identity.get("principalId", "unknown"), user_type


def extract_user_info(record: dict) -> tuple[str, str]:
    """
    Extract user identifier and type from record.

    Args:
        record: CloudTrail event record

    Returns:
        Tuple of (user_identifier, user_type)

    """
    if "userIdentity" not in record:
        return "Unknown", "unknown"

    user_identity = record["userIdentity"]
    user_type = user_identity.get("type", "unknown").lower()

    # Map user types to extraction functions
    extractors = {
        "iamuser": lambda: _extract_iam_user_info(user_identity),
        "assumedrole": lambda: _extract_assumed_role_info(user_identity),
        "root": lambda: _extract_root_user_info(user_identity),
        "samluser": lambda: _extract_federated_user_info(user_identity, user_type),
        "webidentityuser": lambda: _extract_federated_user_info(user_identity, user_type),
    }

    # Use appropriate extractor
    if user_type in extractors:
        return extractors[user_type]()
    if "accessKeyId" in user_identity:
        return _extract_access_key_user_info(user_identity)
    return _extract_default_user_info(user_identity, user_type)


def extract_comprehensive_resources(record: dict) -> tuple[set[str], set[str], set[str]]:
    """
    Extract comprehensive resource information for policy generation.

    Args:
        record: CloudTrail event record

    Returns:
        Tuple of (resource_arns, resource_types, conditions)

    """
    resource_arns = set()
    resource_types = set()
    conditions = set()

    # Extract from Resources field
    if "resources" in record:
        for resource in record["resources"]:
            if "ARN" in resource:
                arn = resource["ARN"]
                resource_arns.add(arn)

                # Extract resource type from ARN
                if arn.startswith("arn:aws:"):
                    parts = arn.split(":")
                    if len(parts) >= 6:
                        service = parts[2]
                        resource_part = parts[5]
                        if "/" in resource_part:
                            resource_type = resource_part.split("/")[0]
                        else:
                            resource_type = resource_part
                        resource_types.add(f"{service}:{resource_type}")

            if "type" in resource:
                resource_types.add(resource["type"])

    # Extract from requestParameters for additional resources
    if record.get("requestParameters"):
        request_params = record["requestParameters"]

        # Common ARN patterns in request parameters
        arn_patterns = [
            r'arn:aws:[^:]+:[^:]*:[^:]*:[^"\s}]+',  # General ARN pattern
        ]

        def extract_arns_from_obj(obj, path=""):
            """Recursively extract ARNs from request parameters."""
            if isinstance(obj, str):
                for pattern in arn_patterns:
                    matches = re.findall(pattern, obj)
                    for match in matches:
                        resource_arns.add(match)
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{path}.{key}" if path else key
                    extract_arns_from_obj(value, new_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    extract_arns_from_obj(item, f"{path}[{i}]")

        extract_arns_from_obj(request_params)

    # Extract from responseElements
    if record.get("responseElements"):
        response_elements = record["responseElements"]

        def extract_from_response(obj, prefix=""):
            """Recursively extract resource identifiers from response elements."""
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key.lower().endswith("arn") and isinstance(value, str) and value.startswith("arn:aws:"):
                        resource_arns.add(value)
                    elif isinstance(value, dict):
                        extract_from_response(value, f"{prefix}.{key}" if prefix else key)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                extract_from_response(item, f"{prefix}.{key}" if prefix else key)

        extract_from_response(response_elements)

    # Extract conditions for policy generation
    if "sourceIPAddress" in record:
        conditions.add(f"IpAddress={record['sourceIPAddress']}")

    if "userAgent" in record:
        conditions.add(f"UserAgent={record['userAgent']}")

    if record.get("vpcEndpointId"):
        conditions.add(f"VpcEndpoint={record['vpcEndpointId']}")

    # Time-based conditions
    if "eventTime" in record:
        event_time = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
        hour = event_time.hour
        conditions.add(f"TimeOfDay={hour:02d}:00-{hour+1:02d}:00")

    return resource_arns, resource_types, conditions


def _parse_cloudtrail_event(event: dict) -> dict | None:
    """Parse CloudTrail event from various formats."""
    # Handle both direct CloudTrail API events and JSON file events
    record = event.get("CloudTrailEvent", event)

    # If CloudTrailEvent is a JSON string, parse it
    if isinstance(record, str):
        try:
            record = json.loads(record)
        except json.JSONDecodeError as e:
            print(f"⚠️ Warning: Could not parse CloudTrailEvent JSON: {e}")
            return None

    # Skip if record is not a dictionary
    if not isinstance(record, dict):
        return None

    return record


def _update_existing_activity(activity: UserActivity, new_activity_data: dict) -> None:
    """Update existing activity with new data."""
    activity.resources.update(new_activity_data["resource_arns"])
    activity.resource_types.update(new_activity_data["resource_types"])
    activity.actions.add(new_activity_data["action"])
    activity.conditions.update(new_activity_data["conditions"])

    if new_activity_data["source_ip"]:
        activity.source_ips.add(new_activity_data["source_ip"])
    if new_activity_data["user_agent"]:
        activity.user_agents.add(new_activity_data["user_agent"])

    activity.count += 1

    # Update timestamps
    event_time = new_activity_data["event_time"]
    if event_time and (activity.first_seen is None or event_time < activity.first_seen):
        activity.first_seen = event_time
    if event_time and (activity.last_seen is None or event_time > activity.last_seen):
        activity.last_seen = event_time


def _create_new_activity(user_data: tuple[str, str], service_data: tuple[str, str, str], activity_data: dict) -> UserActivity:
    """Create new UserActivity object."""
    user_identifier, user_type = user_data
    service, event_name, event_source = service_data

    return UserActivity(
        user_identifier=user_identifier,
        user_type=user_type,
        service=service,
        event_name=event_name,
        event_source=event_source,
        resources=activity_data["resource_arns"],
        resource_types=activity_data["resource_types"],
        actions={activity_data["action"]},
        request_parameters=activity_data["request_parameters"],
        conditions=activity_data["conditions"],
        source_ips={activity_data["source_ip"]} if activity_data["source_ip"] else set(),
        user_agents={activity_data["user_agent"]} if activity_data["user_agent"] else set(),
        count=1,
        first_seen=activity_data["event_time"],
        last_seen=activity_data["event_time"],
    )


def _extract_activity_data(record: dict) -> dict:
    """Extract all activity data from a CloudTrail record."""
    # Extract basic event information
    service = record["eventSource"].replace(".amazonaws.com", "")
    event_name = record["eventName"]
    event_source = record["eventSource"]
    action = f"{service}:{event_name}"

    # Extract resource information
    resource_arns, resource_types, conditions = extract_comprehensive_resources(record)

    # Extract timestamp
    event_time = None
    if "eventTime" in record:
        with contextlib.suppress(ValueError, TypeError):
            event_time = datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))

    # Extract additional information
    source_ip = record.get("sourceIPAddress", "")
    user_agent = record.get("userAgent", "")
    request_parameters = record.get("requestParameters", {})

    return {
        "service": service,
        "event_name": event_name,
        "event_source": event_source,
        "action": action,
        "resource_arns": resource_arns,
        "resource_types": resource_types,
        "conditions": conditions,
        "event_time": event_time,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "request_parameters": request_parameters,
    }


def analyze_user_activity(events: list, criteria: UserSearchCriteria) -> dict[str, UserActivity]:
    """
    Analyze CloudTrail events for specific user activity.

    Args:
        events: List of CloudTrail events
        criteria: Search criteria

    Returns:
        Dictionary mapping API calls to UserActivity objects

    """
    user_activities = defaultdict(lambda: UserActivity("", "", "", "", "", set(), set(), set(), {}, set(), set(), set(), 0))

    matched_events = 0
    total_events = 0

    for event in events:
        total_events += 1

        record = _parse_cloudtrail_event(event)
        if record is None:
            continue

        # Check if this event matches our search criteria
        if not matches_user_criteria(record, criteria):
            continue

        matched_events += 1

        # Extract basic event information
        if "eventSource" not in record or "eventName" not in record:
            continue

        # Extract all activity data
        activity_data = _extract_activity_data(record)
        api_call_key = activity_data["action"]

        # Extract user information
        user_identifier, user_type = extract_user_info(record)

        # Update or create user activity
        if api_call_key in user_activities:
            _update_existing_activity(user_activities[api_call_key], activity_data)
        else:
            user_data = (user_identifier, user_type)
            service_data = (activity_data["service"], activity_data["event_name"], activity_data["event_source"])
            user_activities[api_call_key] = _create_new_activity(user_data, service_data, activity_data)

    print("\n📊 Analysis complete:")
    print(f"   • Total events processed: {total_events:,}")
    print(f"   • Events matching user criteria: {matched_events:,}")
    print(f"   • Unique API calls by user: {len(user_activities)}")

    return dict(user_activities)


def process_cloudtrail_file(file_path: Path, criteria: UserSearchCriteria) -> dict[str, UserActivity]:
    """
    Process a CloudTrail log file (JSON or .gz).

    Args:
        file_path: Path to the log file
        criteria: Search criteria

    Returns:
        Dictionary of user activities

    """
    try:
        print(f"  📄 Processing: {file_path.name}")

        # Handle gzipped files
        if file_path.suffix == ".gz":
            with gzip.open(file_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with file_path.open(encoding="utf-8") as f:
                data = json.load(f)

        events = []

        # Handle different JSON structures
        if "Records" in data:
            # Original CloudTrail log format
            events = data["Records"]
        elif "Events" in data:
            # get_events format
            events = data["Events"]
        else:
            print(f"    ⚠️ Unknown JSON format in {file_path}")
            return {}

        print(f"    📝 Found {len(events)} events")
        return analyze_user_activity(events, criteria)

    except FileNotFoundError:
        print(f"    ❌ File not found: {file_path}")
        return {}
    except json.JSONDecodeError as e:
        print(f"    ❌ JSON decode error in {file_path}: {e}")
        return {}
    except (OSError, PermissionError) as e:
        print(f"    ❌ Error processing {file_path}: {e}")
        return {}


def _print_activity_header(activities: dict[str, UserActivity], criteria: UserSearchCriteria) -> None:
    """Print the header section of activity results."""
    first_activity = next(iter(activities.values()))
    print(f"🔍 Search Criteria: {criteria.search_type} = '{criteria.search_value}'")
    print(f"👤 User: {first_activity.user_identifier} (Type: {first_activity.user_type})")
    print(f"📊 Total unique API calls: {len(activities)}")


def _print_activity_summary(activities: dict[str, UserActivity]) -> None:
    """Print summary statistics for activities."""
    total_calls = sum(activity.count for activity in activities.values())
    unique_services = len({activity.service for activity in activities.values()})
    all_resources = set()

    for activity in activities.values():
        all_resources.update(activity.resources)

    print(f"📈 Total API calls made: {total_calls:,}")
    print(f"🔧 AWS services used: {unique_services}")
    print(f"📋 Unique resources accessed: {len(all_resources)}")
    print()


def _print_activity_timestamps(activity: UserActivity) -> None:
    """Print timestamp information for an activity."""
    if not (activity.first_seen and activity.last_seen):
        return

    if activity.first_seen == activity.last_seen:
        print(f"      ⏰ Used on: {activity.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print(f"      ⏰ First used: {activity.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"      ⏰ Last used: {activity.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")


def _print_activity_resources(activity: UserActivity) -> None:
    """Print resource information for an activity."""
    if not activity.resources:
        return

    print("      🎯 Resources accessed:")
    for i, resource in enumerate(sorted(activity.resources)):
        if i >= MAX_RESOURCES_DISPLAY:
            print(f"         ... and {len(activity.resources) - MAX_RESOURCES_DISPLAY} more resources")
            break
        print(f"         • {resource}")


def _print_activity_resource_types(activity: UserActivity) -> None:
    """Print resource types for an activity."""
    if not activity.resource_types:
        return

    resource_types_str = ", ".join(sorted(activity.resource_types)[:MAX_RESOURCE_TYPES_DISPLAY])
    if len(activity.resource_types) > MAX_RESOURCE_TYPES_DISPLAY:
        resource_types_str += f" ... (+{len(activity.resource_types) - MAX_RESOURCE_TYPES_DISPLAY} more)"
    print(f"      📋 Resource types: {resource_types_str}")


def _print_activity_source_ips(activity: UserActivity) -> None:
    """Print source IP information for an activity."""
    if len(activity.source_ips) > 1:
        ips_str = ", ".join(sorted(activity.source_ips)[:MAX_SOURCE_IPS_DISPLAY])
        if len(activity.source_ips) > MAX_SOURCE_IPS_DISPLAY:
            ips_str += f" ... (+{len(activity.source_ips) - MAX_SOURCE_IPS_DISPLAY} more)"
        print(f"      🌐 Source IPs: {ips_str}")
    elif activity.source_ips:
        print(f"      🌐 Source IP: {next(iter(activity.source_ips))}")


def print_user_activity_results(activities: dict[str, UserActivity], criteria: UserSearchCriteria):
    """
    Print the user activity analysis results.

    Args:
        activities: Dictionary of user activities
        criteria: Search criteria used

    """
    if not activities:
        print("\n❌ No activities found for the specified user.")
        return

    print(f"\n{'='*80}")
    print("👤 USER ACTIVITY ANALYSIS RESULTS")
    print(f"{'='*80}")

    # Print header information
    _print_activity_header(activities, criteria)

    # Print summary statistics
    _print_activity_summary(activities)

    # Sort by service, then by call count (descending)
    sorted_activities = sorted(
        activities.items(),
        key=lambda x: (x[1].service, -x[1].count, x[1].event_name),
    )

    current_service = None
    for _api_call, activity in sorted_activities:
        # Print service header if changed
        if current_service != activity.service:
            current_service = activity.service
            print(f"\n🔹 SERVICE: {activity.service.upper()}")
            print("-" * 40)

        print(f"   📞 {activity.event_name} (called {activity.count} times)")

        # Show time range if available
        _print_activity_timestamps(activity)

        # Show resources (limited for readability)
        _print_activity_resources(activity)

        # Show resource types
        _print_activity_resource_types(activity)

        # Show source IPs if multiple
        _print_activity_source_ips(activity)

        print()


def save_user_activity_analysis(activities: dict[str, UserActivity], criteria: UserSearchCriteria, filename: str) -> bool:
    """
    Save user activity analysis to JSON file.

    Args:
        activities: Dictionary of user activities
        criteria: Search criteria
        filename: Output filename

    Returns:
        True if successful

    """
    try:
        # Convert UserActivity objects to dictionaries
        analysis_data = {}
        for api_call, activity in activities.items():
            analysis_data[api_call] = {
                "user_identifier": activity.user_identifier,
                "user_type": activity.user_type,
                "service": activity.service,
                "event_name": activity.event_name,
                "event_source": activity.event_source,
                "count": activity.count,
                "first_seen": activity.first_seen.isoformat() if activity.first_seen else None,
                "last_seen": activity.last_seen.isoformat() if activity.last_seen else None,
                "resources": sorted(activity.resources),
                "resource_types": sorted(activity.resource_types),
                "actions": sorted(activity.actions),
                "conditions": sorted(activity.conditions),
                "source_ips": sorted(activity.source_ips),
                "user_agents": sorted(activity.user_agents),
            }

        # Calculate summary statistics
        total_calls = sum(activity.count for activity in activities.values())
        unique_services = len({activity.service for activity in activities.values()})
        all_resources = set()
        for activity in activities.values():
            all_resources.update(activity.resources)

        output_data = {
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "search_criteria": {
                "search_type": criteria.search_type,
                "search_value": criteria.search_value,
                "case_sensitive": criteria.case_sensitive,
            },
            "summary": {
                "user_identifier": next(iter(activities.values())).user_identifier if activities else "Unknown",
                "user_type": next(iter(activities.values())).user_type if activities else "Unknown",
                "unique_api_calls": len(activities),
                "total_api_calls": total_calls,
                "unique_services": unique_services,
                "unique_resources": len(all_resources),
            },
            "activities": analysis_data,
        }

        with Path(filename).open("w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)

    except (OSError, PermissionError, json.JSONEncodeError) as e:
        print(f"❌ Error saving analysis: {e}")
        return False
    else:
        print(f"✅ User activity analysis saved to: {filename}")
        return True


def _get_log_files_directory() -> Path:
    """Get and validate the CloudTrail logs directory."""
    print("\n📂 CLOUDTRAIL LOGS LOCATION")
    print("=" * 40)
    directory_input = input("Enter directory path containing CloudTrail logs [default: ./cloudtrail_logs]: ").strip()
    directory = Path(directory_input) if directory_input else Path("./cloudtrail_logs")

    if not directory.exists():
        print(f"❌ Directory does not exist: {directory}")
        sys.exit(1)

    return directory


def _find_log_files(directory: Path) -> list[Path]:
    """Find and validate CloudTrail log files."""
    json_files = list(directory.rglob("*.json"))
    gz_files = list(directory.rglob("*.gz"))
    log_files = json_files + gz_files

    if not log_files:
        print(f"❌ No CloudTrail log files found in: {directory}")
        print("💡 Looking for .json and .gz files recursively")
        sys.exit(1)

    print(f"\n📂 Found {len(log_files)} CloudTrail log files in: {directory}")
    print(f"   • JSON files: {len(json_files)}")
    print(f"   • Gzipped files: {len(gz_files)}")

    return log_files


def _process_all_log_files(log_files: list[Path], criteria: UserSearchCriteria) -> dict[str, UserActivity]:
    """Process all log files and merge results."""
    all_activities = {}
    processed_files = 0

    for file_path in log_files:
        file_activities = process_cloudtrail_file(file_path, criteria)
        processed_files += 1

        # Merge results
        for api_call, activity in file_activities.items():
            if api_call in all_activities:
                existing_activity = all_activities[api_call]
                existing_activity.resources.update(activity.resources)
                existing_activity.resource_types.update(activity.resource_types)
                existing_activity.actions.update(activity.actions)
                existing_activity.conditions.update(activity.conditions)
                existing_activity.source_ips.update(activity.source_ips)
                existing_activity.user_agents.update(activity.user_agents)
                existing_activity.count += activity.count

                # Update timestamps using combined if statements
                if activity.first_seen and (existing_activity.first_seen is None or activity.first_seen < existing_activity.first_seen):
                    existing_activity.first_seen = activity.first_seen
                if activity.last_seen and (existing_activity.last_seen is None or activity.last_seen > existing_activity.last_seen):
                    existing_activity.last_seen = activity.last_seen
            else:
                all_activities[api_call] = activity

    print(f"\n✅ Processed {processed_files} files")
    return all_activities


def _handle_save_analysis(all_activities: dict[str, UserActivity], criteria: UserSearchCriteria) -> None:
    """Handle saving the analysis to file."""
    save_analysis = input("\n💾 Save analysis to file? (y/n) [default: y]: ").strip().lower()
    if save_analysis in ["", "y", "yes"]:
        default_filename = f"user_activity_{criteria.search_value.replace('@', '_').replace(':', '_')}.json"
        analysis_file = input(f"Enter filename [default: {default_filename}]: ").strip()
        if not analysis_file:
            analysis_file = default_filename

        save_user_activity_analysis(all_activities, criteria, analysis_file)


def _print_policy_generation_hints(all_activities: dict[str, UserActivity]) -> None:
    """Print hints for policy generation."""
    print("\n🔐 POLICY GENERATION HINTS:")
    print("=" * 40)
    unique_actions = set()
    unique_resources = set()

    for activity in all_activities.values():
        unique_actions.update(activity.actions)
        unique_resources.update(activity.resources)

    print(f"📋 Actions needed in policy: {len(unique_actions)}")
    print("   Example actions:")
    for _i, action in enumerate(sorted(unique_actions)[:MAX_ACTIONS_DISPLAY]):
        print(f"     • {action}")
    if len(unique_actions) > MAX_ACTIONS_DISPLAY:
        print(f"     ... and {len(unique_actions) - MAX_ACTIONS_DISPLAY} more actions")

    if unique_resources:
        print(f"\n🎯 Resources needed in policy: {len(unique_resources)}")
        print("   Example resources:")
        for _i, resource in enumerate(sorted(unique_resources)[:MAX_SUMMARY_RESOURCES_DISPLAY]):
            print(f"     • {resource}")
        if len(unique_resources) > MAX_SUMMARY_RESOURCES_DISPLAY:
            print(f"     ... and {len(unique_resources) - MAX_SUMMARY_RESOURCES_DISPLAY} more resources")
    else:
        print("\n🎯 Note: Some actions may not require specific resources (use '*')")


def _print_troubleshooting_tips(criteria: UserSearchCriteria) -> None:
    """Print troubleshooting tips when no activities found."""
    print(f"\n❌ No activities found for user: {criteria.search_type} = '{criteria.search_value}'")
    print("\n💡 Troubleshooting tips:")
    print("   • Check if the username/access key is correct")
    print("   • Try a case-insensitive search")
    print("   • Verify CloudTrail was logging during the user's activity period")
    print("   • Check if logs are from the correct time period")


def main():
    """Main function to orchestrate the user activity analysis."""
    print("👤 CloudTrail User Activity Analyzer")
    print("=" * 60)
    print("This tool analyzes CloudTrail logs to find all API calls made by a specific user.")
    print("Perfect for generating least privilege IAM policies!\n")

    # Get search criteria
    criteria = get_user_search_criteria()

    # Get directory containing CloudTrail logs
    directory = _get_log_files_directory()

    # Find CloudTrail log files (JSON and .gz)
    log_files = _find_log_files(directory)

    # Process all files
    print(f"\n🔍 Searching for activities by: {criteria.search_type} = '{criteria.search_value}'")
    print("=" * 60)

    all_activities = _process_all_log_files(log_files, criteria)

    # Print results and handle saving
    if all_activities:
        print_user_activity_results(all_activities, criteria)
        _handle_save_analysis(all_activities, criteria)
        _print_policy_generation_hints(all_activities)
    else:
        _print_troubleshooting_tips(criteria)


if __name__ == "__main__":
    main()
