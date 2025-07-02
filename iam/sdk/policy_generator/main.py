#!/usr/bin/env python3
# main.py
"""
CloudTrail Analysis Orchestrator.

Main entry point for the CloudTrail log analysis and least privilege policy generation workflow.
Provides a unified interface to download logs, analyze user activity, and generate IAM policies.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import NoReturn

# Constants
MAX_FILES_DISPLAY = 3  # Maximum files to display in status
VALID_MENU_CHOICES = ["1", "2", "3", "4", "5", "6", "7"]

# AWS S3 API Pricing (USD, as of 2025)
S3_LIST_COST_PER_1000 = 0.0005  # LIST requests
S3_GET_COST_PER_1000 = 0.0004   # GET requests

# Module availability check
MODULES = {
    "download_cloudtrail_logs": "download_cloudtrail_logs.py",
    "unique_events_from_logs": "unique_events_from_logs.py",
    "generate_policy": "generate_policy.py",
}


def check_module_availability() -> dict[str, bool]:
    """Check which modules are available in the current directory."""
    available = {}
    for module_name, filename in MODULES.items():
        module_path = Path(filename)
        available[module_name] = module_path.exists()
    return available


def print_banner():
    """Print the application banner."""
    print("="*80)
    print("🔐 CloudTrail Analysis & Least Privilege Policy Generator")
    print("="*80)
    print("Complete workflow for analyzing AWS CloudTrail logs and generating")
    print("minimal IAM policies based on actual user activity.")
    print()


def print_workflow_overview():
    """Print an overview of the workflow."""
    print("📋 WORKFLOW OVERVIEW:")
    print("="*50)
    print("1. 📥 Download CloudTrail logs from S3 bucket")
    print("2. 🔍 Analyze user activity from downloaded logs")
    print("3. 🔐 Generate least privilege IAM policy")
    print("4. 🚀 Deploy policy to AWS (manual step)")
    print()


def print_main_menu():
    """Print the main menu options."""
    print("🎯 MAIN MENU:")
    print("="*30)
    print("1. 📥 Download CloudTrail Logs")
    print("2. 🔍 Analyze User Activity")
    print("3. 🔐 Generate IAM Policy")
    print("4. 🔄 Run Complete Workflow")
    print("5. 📊 Show Status")
    print("6. ❓ Help")
    print("7. 🚪 Exit")
    print()


def run_module(module_name: str, description: str) -> bool:
    """
    Run a module and handle errors.

    Args:
        module_name: Name of the module to run
        description: Human-readable description

    Returns:
        True if successful, False otherwise

    """
    filename = MODULES.get(module_name)
    if not filename:
        print(f"❌ Unknown module: {module_name}")
        return False

    if not Path(filename).exists():
        print(f"❌ Module not found: {filename}")
        return False

    print(f"\n🚀 Starting: {description}")
    print("="*60)

    try:
        # Run the module as a subprocess (trusted internal modules only)
        subprocess.run([sys.executable, filename], check=True)  # noqa: S603

    except subprocess.CalledProcessError as e:
        print(f"\n❌ {description} failed with exit code: {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"\n❌ Python interpreter not found: {sys.executable}")
        return False
    except KeyboardInterrupt:
        print(f"\n⚠️  {description} interrupted by user")
        return False
    else:
        print(f"\n✅ {description} completed successfully!")
        return True


def estimate_download_cost() -> dict[str, float] | None:
    """
    Estimate the cost of downloading CloudTrail logs.

    Returns:
        Dictionary with cost estimates or None if estimation fails

    """
    print("\n💰 COST ESTIMATION")
    print("="*40)
    print("Let's estimate the cost of downloading CloudTrail logs...")
    print()

    try:
        # Get basic parameters for estimation
        print("Please provide some basic information for cost estimation:")

        # Date range
        date_range = input("📅 How many days of logs? [default: 7]: ").strip()
        days = int(date_range) if date_range.isdigit() else 7

        # Regions
        regions_input = input("🌍 How many AWS regions? [default: 1]: ").strip()
        regions = int(regions_input) if regions_input.isdigit() else 1

        # Activity level
        print("\n📊 Activity level:")
        print("   1. Low (small account, few resources)")
        print("   2. Medium (typical production account)")
        print("   3. High (large account, many resources)")
        activity_input = input("Select activity level (1-3) [default: 2]: ").strip()
        activity_level = int(activity_input) if activity_input in ["1", "2", "3"] else 2

        # Estimate API calls
        # Base estimates per day per region
        base_list_calls = {"1": 10, "2": 50, "3": 200}[str(activity_level)]
        base_get_calls = {"1": 100, "2": 500, "3": 2000}[str(activity_level)]

        # Calculate total calls
        total_list_calls = base_list_calls * days * regions
        total_get_calls = base_get_calls * days * regions

        # Calculate costs
        list_cost = (total_list_calls / 1000) * S3_LIST_COST_PER_1000
        get_cost = (total_get_calls / 1000) * S3_GET_COST_PER_1000
        total_cost = list_cost + get_cost

        # Display estimate
        print("\n📊 ESTIMATED COSTS:")
        print("="*30)
        print(f"📅 Date range: {days} days")
        print(f"🌍 Regions: {regions}")
        print(f"📈 Activity level: {['Low', 'Medium', 'High'][activity_level-1]}")
        print()
        print(f"📋 LIST requests: ~{total_list_calls:,}")
        print(f"📥 GET requests: ~{total_get_calls:,}")
        print(f"🔢 Total requests: ~{total_list_calls + total_get_calls:,}")
        print()
        print(f"💸 LIST costs: ${list_cost:.6f}")
        print(f"💸 GET costs: ${get_cost:.6f}")
        print(f"💸 Total API costs: ${total_cost:.6f}")
        print()

        if total_cost < 0.01:
            print("💡 Estimated cost is negligible (< $0.01)")
        elif total_cost < 0.10:
            print("💡 Estimated cost is very low (< $0.10)")
        elif total_cost < 1.00:
            print("💡 Estimated cost is low (< $1.00)")
        else:
            print("⚠️  Estimated cost is significant (> $1.00)")

        print("\n🔍 Note: This is an estimate only. Actual costs may vary.")
        print("Data transfer costs are not included (depend on your location).")

    except (ValueError, KeyboardInterrupt):
        print("\n❌ Cost estimation cancelled or invalid input")
        return None

    else:
        return {
            "days": days,
            "regions": regions,
            "activity_level": activity_level,
            "list_calls": total_list_calls,
            "get_calls": total_get_calls,
            "list_cost": list_cost,
            "get_cost": get_cost,
            "total_cost": total_cost,
        }


def download_cloudtrail_logs() -> bool:
    """Download CloudTrail logs from S3 with cost estimation."""
    print("\n📥 CLOUDTRAIL LOG DOWNLOAD")
    print("="*50)

    # Show cost estimation first
    cost_estimate = estimate_download_cost()

    if cost_estimate:
        print(f"\n💰 Estimated cost: ${cost_estimate['total_cost']:.6f}")
        confirm = input("\nProceed with download? (y/n): ").strip().lower()
        if confirm not in ["y", "yes"]:
            print("❌ Download cancelled")
            return False

    return run_module("download_cloudtrail_logs", "CloudTrail Log Download")


def analyze_user_activity() -> bool:
    """Analyze user activity from CloudTrail logs."""
    return run_module("unique_events_from_logs", "User Activity Analysis")


def generate_iam_policy() -> bool:
    """Generate least privilege IAM policy."""
    return run_module("generate_policy", "IAM Policy Generation")


def run_complete_workflow() -> None:
    """Run the complete workflow from start to finish."""
    print("\n🔄 RUNNING COMPLETE WORKFLOW")
    print("="*50)
    print("This will run all steps in sequence:")
    print("1. Download CloudTrail logs")
    print("2. Analyze user activity")
    print("3. Generate IAM policy")
    print()

    confirm = input("Continue with complete workflow? (y/n): ").strip().lower()
    if confirm not in ["y", "yes"]:
        print("❌ Workflow cancelled")
        return

    workflow_start = time.time()
    steps_completed = 0
    total_steps = 3

    # Step 1: Download logs
    print(f"\n📥 STEP 1/{total_steps}: Downloading CloudTrail Logs")
    if download_cloudtrail_logs():
        steps_completed += 1
        print("✅ Step 1 completed successfully")
    else:
        print("❌ Step 1 failed - workflow stopped")
        return

    # Step 2: Analyze activity
    print(f"\n🔍 STEP 2/{total_steps}: Analyzing User Activity")
    if analyze_user_activity():
        steps_completed += 1
        print("✅ Step 2 completed successfully")
    else:
        print("❌ Step 2 failed - workflow stopped")
        return

    # Step 3: Generate policy
    print(f"\n🔐 STEP 3/{total_steps}: Generating IAM Policy")
    if generate_iam_policy():
        steps_completed += 1
        print("✅ Step 3 completed successfully")
    else:
        print("❌ Step 3 failed - workflow stopped")
        return

    # Workflow complete
    workflow_time = time.time() - workflow_start
    print("\n🎉 WORKFLOW COMPLETE!")
    print("="*50)
    print(f"✅ All {steps_completed}/{total_steps} steps completed successfully")
    print(f"⏱️  Total time: {workflow_time:.1f} seconds")
    print("\n📋 Next Steps:")
    print("1. Review the generated IAM policy files")
    print("2. Test the policy in a non-production environment")
    print("3. Deploy to AWS IAM when ready")


def show_status() -> None:
    """Show the current status of files and modules."""
    print("\n📊 SYSTEM STATUS")
    print("="*40)

    # Check module availability
    available = check_module_availability()
    print("📦 Available Modules:")
    for module_name, filename in MODULES.items():
        status = "✅" if available[module_name] else "❌"
        print(f"   {status} {filename}")

    print()

    # Check for generated files
    print("📁 Generated Files:")
    file_patterns = [
        ("cloudtrail_logs/", "Downloaded CloudTrail logs"),
        ("user_activity_*.json", "User activity analysis"),
        ("iam_policy_*_aws_ready.json", "AWS-ready IAM policy"),
        ("iam_policy_*_complete.json", "Complete IAM policy with metadata"),
    ]

    current_dir = Path()
    for pattern, description in file_patterns:
        if pattern.endswith("/"):
            # Directory check
            dir_path = Path(pattern.rstrip("/"))
            if dir_path.exists() and dir_path.is_dir():
                file_count = len(list(dir_path.rglob("*")))
                print(f"   ✅ {description}: {file_count} files in {pattern}")
            else:
                print(f"   ❌ {description}: {pattern} not found")
        else:
            # File pattern check
            files = list(current_dir.glob(pattern))
            if files:
                print(f"   ✅ {description}: {len(files)} files found")
                for file in files[:MAX_FILES_DISPLAY]:  # Show first few files
                    print(f"      📄 {file.name}")
                if len(files) > MAX_FILES_DISPLAY:
                    print(f"      ... and {len(files) - MAX_FILES_DISPLAY} more")
            else:
                print(f"   ❌ {description}: No files matching {pattern}")


def show_help() -> None:
    """Show detailed help information."""
    print("\n❓ HELP & INFORMATION")
    print("="*40)
    print()
    print("🔍 WHAT THIS TOOL DOES:")
    print("This tool helps you create least privilege IAM policies by:")
    print("1. Downloading your CloudTrail logs from S3")
    print("2. Analyzing what API calls a specific user actually made")
    print("3. Generating a minimal IAM policy with only required permissions")
    print()

    print("📋 PREREQUISITES:")
    print("• AWS CLI configured with appropriate credentials")
    print("• CloudTrail logging enabled in your AWS account")
    print("• S3 bucket with CloudTrail logs")
    print("• Python 3.8+ with required dependencies")
    print()

    print("🔧 MODULE DESCRIPTIONS:")
    print("• download_cloudtrail_logs.py: Downloads logs from S3 with parallel processing")
    print("• unique_events_from_logs.py: Analyzes logs to find user-specific API calls")
    print("• generate_policy.py: Creates AWS-ready IAM policies from analysis")
    print()

    print("🚀 QUICK START:")
    print("1. Run option 4 (Complete Workflow) for first-time setup")
    print("2. Or run individual steps if you have existing data")
    print("3. Review generated policy files before deploying")
    print()

    print("💡 TIPS:")
    print("• Use option 5 (Show Status) to check what files exist")
    print("• Generated policies are ready to copy-paste into AWS console")
    print("• Always test policies in non-production environments first")


def get_user_choice() -> str:
    """Get and validate user menu choice."""
    try:
        while True:
            choice = input("Enter your choice (1-7): ").strip()
            if choice in VALID_MENU_CHOICES:
                return choice
            print("❌ Invalid choice. Please enter a number from 1-7.")
    except (KeyboardInterrupt, EOFError):
        print("\n\n🚪 Goodbye!")
        sys.exit(0)


def handle_missing_modules(available: dict[str, bool]) -> None:
    """Handle missing modules gracefully."""
    missing = [name for name, avail in available.items() if not avail]
    if missing:
        print("⚠️  WARNING: Missing modules detected!")
        print("="*40)
        for module in missing:
            print(f"❌ {MODULES[module]} not found")
        print()
        print("Please ensure all required files are in the current directory.")
        print("Some functionality may not be available.")
        print()


def handle_menu_choice(choice: str, available: dict[str, bool]) -> None:
    """
    Handle a specific menu choice.

    Args:
        choice: Menu choice string
        available: Dictionary of module availability

    """
    if choice == "1":
        if available["download_cloudtrail_logs"]:
            download_cloudtrail_logs()
        else:
            print("❌ CloudTrail log downloader not available")

    elif choice == "2":
        if available["unique_events_from_logs"]:
            analyze_user_activity()
        else:
            print("❌ User activity analyzer not available")

    elif choice == "3":
        if available["generate_policy"]:
            generate_iam_policy()
        else:
            print("❌ Policy generator not available")

    elif choice == "4":
        if all(available.values()):
            run_complete_workflow()
        else:
            print("❌ Cannot run complete workflow - some modules are missing")
            show_status()

    elif choice == "5":
        show_status()

    elif choice == "6":
        show_help()

    elif choice == "7":
        print("\n🚪 Thank you for using CloudTrail Analysis Tool!")
        print("Remember to test your generated policies before production deployment.")
        sys.exit(0)


def main() -> NoReturn:
    """Main application loop."""
    print_banner()

    # Check module availability
    available = check_module_availability()
    handle_missing_modules(available)

    print_workflow_overview()

    while True:
        print_main_menu()
        choice = get_user_choice()

        handle_menu_choice(choice, available)

        # Pause before showing menu again
        input("\nPress Enter to continue...")
        print("\n" + "="*80)


if __name__ == "__main__":
    main()
