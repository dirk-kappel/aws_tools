#!/usr/bin/env python3
"""
CloudTrail S3 Log Downloader.

Downloads CloudTrail logs from S3 bucket with date range filtering.
Handles the standard CloudTrail S3 prefix structure and provides progress tracking.
Optimized with parallel processing for faster downloads.
"""

from __future__ import annotations

import gzip
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# Constants
MAX_WORKERS = 10  # Number of parallel download threads
LIST_WORKERS = 5  # Number of parallel listing threads
BYTES_PER_KB = 1024  # Conversion constant
MIN_PATH_PARTS = 7   # Minimum parts in CloudTrail S3 path
MAX_DAILY_FILES_DISPLAY = 10  # Max files per day to display
COST_THRESHOLD = 0.01  # Threshold for cost warnings
SIZE_UNIT_THRESHOLD = 1024  # Threshold for size unit conversion


class CloudTrailDownloader:
    """Downloads CloudTrail logs from S3 with date filtering and parallel processing."""

    def __init__(self, bucket_name: str, bucket_region: str, account_id: str, max_workers: int = MAX_WORKERS, list_workers: int = LIST_WORKERS):
        """Initialize the downloader."""
        self.bucket_name = bucket_name
        self.bucket_region = bucket_region
        self.account_id = account_id
        self.max_workers = max_workers
        self.list_workers = list_workers

        # Track API request counts for cost analysis
        self.list_requests = 0
        self.get_requests = 0
        self.request_lock = threading.Lock()

        try:
            # Initialize S3 client in the bucket's region
            self.s3_client = boto3.client("s3", region_name=bucket_region)
            self.sts_client = boto3.client("sts")
        except NoCredentialsError:
            print("❌ AWS credentials not found. Please configure your credentials.")
            print("   Run 'aws configure' or set environment variables.")
            sys.exit(1)

    @staticmethod
    def get_account_id() -> str:
        """
        Get the current AWS account ID using STS.

        Returns:
            AWS account ID

        """
        try:
            sts_client = boto3.client("sts")
            response = sts_client.get_caller_identity()
        except ClientError as e:
            print(f"❌ Error getting account ID: {e}")
            sys.exit(1)
        except NoCredentialsError:
            print("❌ AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
        else:
            account_id = response["Account"]
            print(f"✅ Detected AWS Account ID: {account_id}")
            return account_id

    def validate_bucket_access(self) -> bool:
        """
        Validate that we can access the specified S3 bucket.

        Returns:
            True if bucket is accessible, False otherwise

        """
        try:
            print(f"🔍 Validating access to bucket: {self.bucket_name}")

            # Try to list objects with a small limit to test access
            self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                MaxKeys=1,
            )

            # Track this LIST request
            with self.request_lock:
                self.list_requests += 1

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchBucket":
                print(f"❌ Bucket does not exist: {self.bucket_name}")
            elif error_code == "AccessDenied":
                print(f"❌ Access denied to bucket: {self.bucket_name}")
                print("💡 Check your AWS permissions for s3:ListBucket and s3:GetObject")
            else:
                print(f"❌ Error accessing bucket {self.bucket_name}: {e}")
            return False
        else:
            print(f"✅ Successfully accessed bucket: {self.bucket_name}")
            return True

    def get_bucket_region(self) -> str:
        """
        Get the region where the S3 bucket is located.

        Returns:
            AWS region of the bucket

        """
        try:
            response = self.s3_client.get_bucket_location(Bucket=self.bucket_name)

            # Note: get_bucket_location is a different API call, not a LIST request
            # It's typically free or very low cost, so we don't track it separately

            # get_bucket_location returns None for us-east-1
            region = response.get("LocationConstraint") or "us-east-1"
        except ClientError as e:
            print(f"❌ Error getting bucket location: {e}")
            # Default to the region we're using
            return self.bucket_region
        else:
            print(f"✅ Bucket {self.bucket_name} is located in region: {region}")
            return region

    def validate_regions(self, regions: list[str]) -> list[str]:
        """
        Validate that the specified regions have CloudTrail logs.

        Args:
            regions: List of regions to validate

        Returns:
            List of validated regions with CloudTrail logs

        """
        print(f"🔍 Validating regions: {', '.join(regions)}")
        validated_regions = []

        for region in regions:
            # Check if any logs exist for this region
            prefix = f"AWSLogs/{self.account_id}/CloudTrail/{region}/"

            try:
                response = self.s3_client.list_objects_v2(
                    Bucket=self.bucket_name,
                    Prefix=prefix,
                    MaxKeys=1,
                )

                # Track this LIST request
                with self.request_lock:
                    self.list_requests += 1

                if response.get("Contents"):
                    validated_regions.append(region)
                    print(f"   ✅ Validated region: {region}")
                else:
                    print(f"   ⚠️ No logs found in region: {region}")
            except ClientError as e:
                print(f"   ❌ Error accessing region {region}: {e}")

        return validated_regions

    def generate_date_prefixes(self, start_date: datetime, end_date: datetime, regions: list[str]) -> list[str]:
        """
        Generate S3 prefixes for all dates in range across regions.

        Args:
            start_date: Start date
            end_date: End date
            regions: List of regions to include

        Returns:
            List of S3 prefixes to search

        """
        prefixes = []
        current_date = start_date

        while current_date <= end_date:
            year = current_date.strftime("%Y")
            month = current_date.strftime("%m")
            day = current_date.strftime("%d")

            for region in regions:
                prefix = f"AWSLogs/{self.account_id}/CloudTrail/{region}/{year}/{month}/{day}/"
                prefixes.append(prefix)

            current_date += timedelta(days=1)

        return prefixes

    def list_log_files(self, prefixes: list[str]) -> list[dict]:
        """
        List all CloudTrail log files for given prefixes using parallel processing.

        Args:
            prefixes: List of S3 prefixes to search

        Returns:
            List of S3 objects (log files)

        """
        all_files = []
        total_prefixes = len(prefixes)
        completed_prefixes = 0
        lock = threading.Lock()

        print(f"📋 Searching {total_prefixes} date/region combinations in parallel...")

        def list_prefix(prefix: str) -> list[dict]:
            """List files for a single prefix."""
            try:
                files = []
                paginator = self.s3_client.get_paginator("list_objects_v2")

                for page in paginator.paginate(Bucket=self.bucket_name, Prefix=prefix):
                    # Track each paginated LIST request
                    with self.request_lock:
                        self.list_requests += 1

                    if "Contents" in page:
                        prefix_files = [obj for obj in page["Contents"] if obj["Key"].endswith(".json.gz")]
                        files.extend(prefix_files)

                with lock:
                    nonlocal completed_prefixes
                    completed_prefixes += 1
                    if files:
                        print(f"   📂 {prefix}: Found {len(files)} log files ({completed_prefixes}/{total_prefixes})")
                    elif completed_prefixes % 10 == 0:
                        print(f"   🔄 Searched {completed_prefixes}/{total_prefixes} prefixes...")

            except ClientError as e:
                with lock:
                    print(f"   ❌ Error searching {prefix}: {e}")
                files = []
            else:
                return files

        # Use ThreadPoolExecutor for parallel listing
        with ThreadPoolExecutor(max_workers=self.list_workers) as executor:
            future_to_prefix = {executor.submit(list_prefix, prefix): prefix for prefix in prefixes}

            for future in as_completed(future_to_prefix):
                files = future.result()
                all_files.extend(files)

        print(f"📊 Total log files found: {len(all_files)}")
        return all_files

    def download_single_file(self, file_obj: dict, output_dir: Path, *, extract: bool = False) -> dict:
        """
        Download a single CloudTrail log file.

        Args:
            file_obj: S3 object to download
            output_dir: Local directory to save files
            extract: Whether to extract .gz files

        Returns:
            Dictionary with download result

        """
        s3_key = file_obj["Key"]
        file_size = file_obj.get("Size", 0)

        # Create local file path maintaining S3 structure
        local_path = output_dir / s3_key
        local_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            # Skip if file already exists and is same size
            if local_path.exists() and local_path.stat().st_size == file_size:
                return {
                    "status": "skipped",
                    "key": s3_key,
                    "size": file_size,
                    "message": "Already exists",
                    "api_calls": 0,  # No API call made
                }

            # Download file
            self.s3_client.download_file(
                Bucket=self.bucket_name,
                Key=s3_key,
                Filename=str(local_path),
            )

            # Track this GET request
            with self.request_lock:
                self.get_requests += 1

            # Extract if requested
            if extract and s3_key.endswith(".json.gz"):
                self._extract_file(local_path)
                # Note: local_path (.gz) is now deleted, JSON file exists

            return {
                "status": "success",
                "key": s3_key,
                "size": file_size,
                "message": "Downloaded and extracted" if extract and s3_key.endswith(".json.gz") else "Downloaded successfully",
                "api_calls": 1,  # One GET request made
            }

        except ClientError as e:
            return {
                "status": "error",
                "key": s3_key,
                "size": 0,
                "message": f"S3 error: {e}",
                "api_calls": 0,  # No successful API call
            }
        except OSError as e:
            return {
                "status": "error",
                "key": s3_key,
                "size": 0,
                "message": f"File system error: {e}",
                "api_calls": 1,  # GET request was made but file write failed
            }

    def download_files(self, files: list[dict], output_dir: Path, *, extract: bool = False) -> None:
        """
        Download CloudTrail log files using parallel processing.

        Args:
            files: List of S3 objects to download
            output_dir: Local directory to save files
            extract: Whether to extract .gz files

        """
        if not files:
            print("❌ No files to download.")
            return

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        total_files = len(files)
        total_size = sum(f.get("Size", 0) for f in files)

        print(f"📥 Downloading {total_files} files to {output_dir}")
        print(f"📊 Total size: {self._format_size(total_size)}")
        print(f"🔧 Using {self.max_workers} parallel download threads")

        # Progress tracking
        completed = 0
        downloaded_size = 0
        skipped = 0
        errors = 0
        lock = threading.Lock()

        def update_progress(result: dict):
            """Update progress counters."""
            nonlocal completed, downloaded_size, skipped, errors

            with lock:
                completed += 1

                if result["status"] == "success":
                    downloaded_size += result["size"]
                elif result["status"] == "skipped":
                    skipped += 1
                    downloaded_size += result["size"]  # Count towards total for progress
                elif result["status"] == "error":
                    errors += 1

                # Show progress every 10 files or on significant milestones
                if completed % 10 == 0 or completed == total_files:
                    progress = (completed / total_files) * 100
                    print(f"   📊 Progress: {progress:.1f}% ({completed}/{total_files}) "
                          f"- Downloaded: {self._format_size(downloaded_size)} "
                          f"- Errors: {errors} - Skipped: {skipped}")

        # Use ThreadPoolExecutor for parallel downloads
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all download tasks
            future_to_file = {
                executor.submit(self.download_single_file, file_obj, output_dir, extract=extract): file_obj
                for file_obj in files
            }

            # Process completed downloads
            for future in as_completed(future_to_file):
                result = future.result()
                update_progress(result)

                # Show individual errors
                if result["status"] == "error":
                    print(f"   ❌ Failed: {result['key']} - {result['message']}")

        print("\n🎉 Download complete!")
        print(f"   ✅ Successfully downloaded: {completed - skipped - errors} files")
        print(f"   ⏭️  Skipped (already exists): {skipped} files")
        print(f"   ❌ Errors: {errors} files")
        print(f"   💾 Total size: {self._format_size(downloaded_size)}")
        print(f"   📂 Location: {output_dir}")

    def _extract_file(self, gz_path: Path) -> None:
        """Extract a .gz file and remove the original to save space."""
        json_path = gz_path.with_suffix("")  # Remove .gz extension

        try:
            with (
                gzip.open(gz_path, "rt", encoding="utf-8") as gz_file,
                json_path.open("w", encoding="utf-8") as json_file,
            ):
                json_file.write(gz_file.read())

            # Remove the .gz file after successful extraction to save space
            gz_path.unlink()
            print(f"   📂 Extracted and removed .gz: {json_path.name}")

        except (OSError, gzip.BadGzipFile) as e:
            print(f"   ⚠️ Failed to extract {gz_path}: {e}")
            # Don't remove the .gz file if extraction failed

    def get_api_cost_summary(self) -> dict:
        """
        Calculate estimated S3 API costs based on requests made.

        Returns:
            Dictionary with cost breakdown

        """
        # S3 pricing (as of 2025, us-east-1 rates)
        list_cost_per_1k = 0.0005  # $0.0005 per 1,000 LIST requests
        get_cost_per_1k = 0.0004   # $0.0004 per 1,000 GET requests

        list_cost = (self.list_requests / 1000) * list_cost_per_1k
        get_cost = (self.get_requests / 1000) * get_cost_per_1k
        total_api_cost = list_cost + get_cost

        return {
            "list_requests": self.list_requests,
            "get_requests": self.get_requests,
            "total_requests": self.list_requests + self.get_requests,
            "list_cost": list_cost,
            "get_cost": get_cost,
            "total_api_cost": total_api_cost,
        }

    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < SIZE_UNIT_THRESHOLD:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= SIZE_UNIT_THRESHOLD
        return f"{size_bytes:.1f} TB"

    def get_log_statistics(self, files: list[dict]) -> dict:
        """Get statistics about the log files."""
        if not files:
            return {}

        total_size = sum(f.get("Size", 0) for f in files)

        # Group by date
        dates = {}
        regions = set()

        for file_obj in files:
            key = file_obj["Key"]
            # Extract date from path: AWSLogs/account/CloudTrail/region/YYYY/MM/DD/filename
            parts = key.split("/")
            if len(parts) >= MIN_PATH_PARTS:
                region = parts[3]
                date_str = f"{parts[4]}-{parts[5]}-{parts[6]}"

                regions.add(region)
                dates[date_str] = dates.get(date_str, 0) + 1

        return {
            "total_files": len(files),
            "total_size": total_size,
            "total_size_formatted": self._format_size(total_size),
            "date_range": f"{min(dates.keys())} to {max(dates.keys())}" if dates else "N/A",
            "regions": sorted(regions),
            "files_per_day": dict(sorted(dates.items())),
        }


def parse_date(date_str: str) -> datetime:
    """Parse date string in YYYY-MM-DD format."""
    try:
        naive_date = datetime.strptime(date_str, "%Y-%m-%d")
        return naive_date.replace(tzinfo=timezone.utc)
    except ValueError as e:
        error_msg = f"Invalid date format. Use YYYY-MM-DD: {e}"
        raise ValueError(error_msg) from e


def get_user_inputs() -> tuple[str, str]:
    """
    Get bucket name and region from user.

    Returns:
        Tuple of (bucket_name, bucket_region)

    """
    print("📦 CloudTrail S3 Configuration:")

    # Get bucket name
    bucket_name = input("Enter S3 bucket name: ").strip()
    if not bucket_name:
        print("❌ Bucket name is required.")
        sys.exit(1)

    # Get bucket region
    print("\nCommon AWS regions:")
    print("  us-east-1 (N. Virginia)")
    print("  us-west-2 (Oregon)")
    print("  eu-west-1 (Ireland)")
    print("  ap-southeast-1 (Singapore)")

    bucket_region = input("Enter S3 bucket region [default: us-east-1]: ").strip()
    if not bucket_region:
        bucket_region = "us-east-1"

    return bucket_name, bucket_region


def get_performance_settings() -> tuple[int, int]:
    """
    Get performance settings from user.

    Returns:
        Tuple of (max_workers, list_workers)

    """
    print("\n⚡ Performance Settings:")
    print(f"   Current defaults: {MAX_WORKERS} download threads, {LIST_WORKERS} listing threads")

    use_defaults = input("Use default performance settings? (y/n) [default: y]: ").strip().lower()

    if use_defaults in ["", "y", "yes"]:
        return MAX_WORKERS, LIST_WORKERS

    # Get custom settings
    try:
        max_workers_input = input(f"Download threads (1-50) [default: {MAX_WORKERS}]: ").strip()
        max_workers = int(max_workers_input) if max_workers_input else MAX_WORKERS
        max_workers = max(1, min(50, max_workers))  # Clamp between 1-50

        list_workers_input = input(f"Listing threads (1-20) [default: {LIST_WORKERS}]: ").strip()
        list_workers = int(list_workers_input) if list_workers_input else LIST_WORKERS
        list_workers = max(1, min(20, list_workers))  # Clamp between 1-20

    except ValueError:
        print("⚠️ Invalid input, using defaults")
        return MAX_WORKERS, LIST_WORKERS
    else:
        print(f"✅ Using {max_workers} download threads, {list_workers} listing threads")
        return max_workers, list_workers


def get_date_range() -> tuple[datetime, datetime]:
    """
    Get date range from user.

    Returns:
        Tuple of (start_date, end_date)

    """
    print("\n📅 Enter date range to download:")
    start_date_str = input("Start date (YYYY-MM-DD): ").strip()
    end_date_str = input("End date (YYYY-MM-DD): ").strip()

    try:
        start_date = parse_date(start_date_str)
        end_date = parse_date(end_date_str)
    except ValueError as e:
        print(f"❌ {e}")
        sys.exit(1)

    if start_date > end_date:
        print("❌ Start date must be before or equal to end date.")
        sys.exit(1)

    # Calculate number of days
    days = (end_date - start_date).days + 1
    print(f"📊 Date range: {start_date_str} to {end_date_str} ({days} days)")

    return start_date, end_date


def get_cloudtrail_regions() -> list[str]:
    """
    Get CloudTrail regions from user.

    Returns:
        List of regions

    """
    print("\n🌍 CloudTrail Region Selection:")
    print("   Note: These are the regions where CloudTrail was logging events")
    print("   Common regions: us-east-1, us-west-2, eu-west-1, ap-southeast-1")
    print("   Enter multiple regions separated by commas")

    regions_input = input("Enter CloudTrail region(s) [default: us-east-1]: ").strip()

    if not regions_input:
        regions = ["us-east-1"]
    else:
        regions = [r.strip() for r in regions_input.split(",") if r.strip()]

    if not regions:
        print("❌ No valid regions specified.")
        sys.exit(1)

    print(f"🌍 Selected CloudTrail regions: {', '.join(regions)}")
    return regions


def validate_and_list_files(downloader: CloudTrailDownloader, start_date: datetime, end_date: datetime, regions: list[str]) -> list[dict]:
    """
    Validate regions and list files.

    Args:
        downloader: CloudTrail downloader instance
        start_date: Start date
        end_date: End date
        regions: List of regions

    Returns:
        List of log files

    """
    # Validate regions have CloudTrail logs
    validated_regions = downloader.validate_regions(regions)

    if not validated_regions:
        print("❌ No CloudTrail logs found in any of the specified regions.")
        print("💡 TIP: Check if CloudTrail is enabled in these regions or try different regions.")
        sys.exit(1)

    if len(validated_regions) != len(regions):
        print(f"⚠️ Continuing with {len(validated_regions)} region(s) that have logs: {', '.join(validated_regions)}")
        confirm = input("Continue? (y/n): ").strip().lower()
        if confirm not in ["y", "yes"]:
            sys.exit(0)

    # Generate prefixes and list files
    prefixes = downloader.generate_date_prefixes(start_date, end_date, validated_regions)
    files = downloader.list_log_files(prefixes)

    if not files:
        print("❌ No CloudTrail log files found for the specified date range and regions.")
        print("💡 TIP: Try a different date range or check if CloudTrail was logging during this period.")
        sys.exit(0)

    return files


def show_download_preview(stats: dict) -> None:
    """
    Show download preview and statistics.

    Args:
        stats: Statistics dictionary

    """
    print("\n📈 DOWNLOAD PREVIEW:")
    print(f"   📁 Total files: {stats['total_files']}")
    print(f"   💾 Total size: {stats['total_size_formatted']}")
    print(f"   📅 Date range: {stats['date_range']}")
    print(f"   🌍 Regions: {', '.join(stats['regions'])}")

    # Show files per day breakdown
    if len(stats["files_per_day"]) <= MAX_DAILY_FILES_DISPLAY:  # Only show if reasonable number of days
        print("   📊 Files per day:")
        for date, count in stats["files_per_day"].items():
            print(f"      {date}: {count} files")


def get_download_settings(stats: dict) -> tuple[Path, bool]:
    """
    Get download settings from user.

    Args:
        stats: Statistics dictionary

    Returns:
        Tuple of (output_dir, extract)

    """
    # Confirm download
    confirm = input(f"\n💾 Download {stats['total_files']} files ({stats['total_size_formatted']})? (y/n): ").strip().lower()
    if confirm not in ["y", "yes"]:
        print("❌ Download cancelled.")
        sys.exit(0)

    # Get output directory
    output_dir_input = input("📂 Output directory [default: ./cloudtrail_logs]: ").strip()
    output_dir = Path(output_dir_input) if output_dir_input else Path("./cloudtrail_logs")

    # Ask about extraction
    extract = input("📂 Extract .gz files to JSON and remove .gz files? (y/n) [default: n]: ").strip().lower() in ["y", "yes"]

    return output_dir, extract


def show_completion_summary(output_dir: Path, cost_summary: dict, max_workers: int, list_workers: int, extract: bool) -> None:
    """
    Show completion summary.

    Args:
        output_dir: Output directory
        cost_summary: Cost summary dictionary
        max_workers: Number of download workers
        list_workers: Number of listing workers
        extract: Whether files were extracted

    """
    print("\n✨ CloudTrail log download complete!")
    print(f"📁 Files saved to: {output_dir.absolute()}")

    # Display API usage and costs
    print("\n💰 S3 API USAGE & COST SUMMARY:")
    print(f"   📋 LIST requests: {cost_summary['list_requests']:,} (bucket validation + region validation + file discovery)")
    print(f"   📥 GET requests: {cost_summary['get_requests']:,} (file downloads)")
    print(f"   🔢 Total requests: {cost_summary['total_requests']:,}")
    print(f"   💸 LIST costs: ${cost_summary['list_cost']:.6f}")
    print(f"   💸 GET costs: ${cost_summary['get_cost']:.6f}")
    print(f"   💸 Total API costs: ${cost_summary['total_api_cost']:.6f}")

    # Show cost efficiency
    if cost_summary["get_requests"] > 0:
        cost_per_file = cost_summary["total_api_cost"] / cost_summary["get_requests"]
        print(f"   📊 Cost per file: ${cost_per_file:.8f}")

    if extract:
        print("\n💡 TIP: Files have been extracted to JSON and .gz files removed to save space.")
        print("💡 TIP: You can now analyze the JSON files directly with other tools.")
        print("💡 TIP: Try using the CloudTrail analyzer: python get_unique_events.py")
    else:
        print("\n💡 TIP: Files are compressed (.gz). Extract them manually or re-run with extraction enabled.")
        print("💡 TIP: You can extract later with: gunzip *.gz")

    print(f"\n⚡ PERFORMANCE: Used {max_workers} parallel downloads and {list_workers} parallel listing threads")

    # Additional cost context
    if cost_summary["total_api_cost"] < COST_THRESHOLD:
        print("💡 COST NOTE: API costs are negligible (< $0.01). Data transfer costs depend on where you run this script.")
    else:
        print(f"💡 COST NOTE: API costs are ${cost_summary['total_api_cost']:.4f}. Data transfer costs depend on where you run this script.")


def format_elapsed_time(elapsed_seconds: float) -> str:
    """
    Format elapsed time in a human-readable format.

    Args:
        elapsed_seconds: Elapsed time in seconds

    Returns:
        Formatted time string

    """
    hours = int(elapsed_seconds // 3600)
    minutes = int((elapsed_seconds % 3600) // 60)
    seconds = elapsed_seconds % 60

    if hours > 0:
        return f"{hours}h {minutes}m {seconds:.1f}s"
    if minutes > 0:
        return f"{minutes}m {seconds:.1f}s"
    return f"{seconds:.1f}s"


def main():
    """Main function to orchestrate CloudTrail log downloading."""
    downloader = None  # Initialize to None for interrupt handling

    try:
        print("📦 CloudTrail S3 Log Downloader")
        print("=" * 60)

        # Get AWS account ID
        print("🔍 Getting AWS account information...")
        account_id = CloudTrailDownloader.get_account_id()

        # Get bucket configuration from user
        bucket_name, bucket_region = get_user_inputs()

        # Get performance settings
        max_workers, list_workers = get_performance_settings()

        start_time = time.time()

        print("\n📋 Configuration Summary:")
        print(f"   🏢 AWS Account ID: {account_id}")
        print(f"   🪣 S3 Bucket: {bucket_name}")
        print(f"   🌍 Bucket Region: {bucket_region}")
        print(f"   ⚡ Performance: {max_workers} download threads, {list_workers} listing threads")

        # Initialize downloader
        downloader = CloudTrailDownloader(bucket_name, bucket_region, account_id, max_workers, list_workers)

        # Validate bucket access
        if not downloader.validate_bucket_access():
            print("❌ Cannot access the specified bucket. Please check your configuration.")
            sys.exit(1)

        # Verify bucket region
        actual_region = downloader.get_bucket_region()
        if actual_region != bucket_region:
            print(f"⚠️ Warning: Bucket is actually in {actual_region}, but you specified {bucket_region}")
            print("Updating configuration to use the correct region...")
            downloader = CloudTrailDownloader(bucket_name, actual_region, account_id, max_workers, list_workers)

        # Get date range
        start_date, end_date = get_date_range()

        # Get CloudTrail regions from user
        regions = get_cloudtrail_regions()

        # Validate regions and list files
        files = validate_and_list_files(downloader, start_date, end_date, regions)

        # Show statistics
        stats = downloader.get_log_statistics(files)
        show_download_preview(stats)

        # Get download settings
        output_dir, extract = get_download_settings(stats)

        # Download files
        downloader.download_files(files, output_dir, extract=extract)

        # Get API cost summary
        cost_summary = downloader.get_api_cost_summary()

        # Show completion summary
        show_completion_summary(output_dir, cost_summary, max_workers, list_workers, extract)

        # Calculate and display elapsed time
        end_time = time.time()
        elapsed_time = end_time - start_time
        formatted_time = format_elapsed_time(elapsed_time)

        print(f"\n⏱️ TOTAL EXECUTION TIME: {formatted_time}")

    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        end_time = time.time()
        elapsed_time = end_time - start_time
        formatted_time = format_elapsed_time(elapsed_time)

        print("\n\n🛑 Download interrupted by user (Ctrl+C)")

        # Show API costs even if interrupted
        if downloader is not None:
            cost_summary = downloader.get_api_cost_summary()
            print("\n💰 S3 API USAGE & COST SUMMARY (up to interruption):")
            print(f"   📋 LIST requests: {cost_summary['list_requests']:,}")
            print(f"   📥 GET requests: {cost_summary['get_requests']:,}")
            print(f"   🔢 Total requests: {cost_summary['total_requests']:,}")
            print(f"   💸 LIST costs: ${cost_summary['list_cost']:.6f}")
            print(f"   💸 GET costs: ${cost_summary['get_cost']:.6f}")
            print(f"   💸 Total API costs: ${cost_summary['total_api_cost']:.6f}")

            if cost_summary["get_requests"] > 0:
                cost_per_file = cost_summary["total_api_cost"] / cost_summary["get_requests"]
                print(f"   📊 Cost per file: ${cost_per_file:.8f}")

            # Additional cost context
            if cost_summary["total_api_cost"] < COST_THRESHOLD:
                print("\n💡 COST NOTE: API costs are negligible (< $0.01). Data transfer costs depend on where you run this script.")
            else:
                print(f"\n💡 COST NOTE: API costs are ${cost_summary['total_api_cost']:.4f}. Data transfer costs depend on where you run this script.")
        else:
            print("\n💡 No API requests were made before interruption.")

        print(f"\n⏱️ EXECUTION TIME BEFORE INTERRUPTION: {formatted_time}")
        print("\n💡 TIP: You can resume downloading by running the script again - already downloaded files will be skipped.")

        # Exit gracefully
        sys.exit(130)  # Standard exit code for SIGINT


if __name__ == "__main__":
    main()
