#!/usr/bin/env python3
# main.py
"""
CloudTrail Analysis Orchestrator

Main entry point for the CloudTrail log analysis and least privilege policy generation workflow.
Provides a unified interface to download logs, analyze user activity, and generate IAM policies.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import NoReturn

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
        # Run the module as a subprocess
        result = subprocess.run([sys.executable, filename], check=True)
        print(f"\n✅ {description} completed successfully!")
        return True

    except subprocess.CalledProcessError as e:
        print(f"\n❌ {description} failed with exit code: {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"\n❌ Python interpreter not found: {sys.executable}")
        return False
    except KeyboardInterrupt:
        print(f"\n⚠️  {description} interrupted by user")
        return False


def download_cloudtrail_logs() -> bool:
    """Download CloudTrail logs from S3."""
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
                for file in files[:3]:  # Show first 3 files
                    print(f"      📄 {file.name}")
                if len(files) > 3:
                    print(f"      ... and {len(files) - 3} more")
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
    while True:
        try:
            choice = input("Enter your choice (1-7): ").strip()
            if choice in ["1", "2", "3", "4", "5", "6", "7"]:
                return choice
            print("❌ Invalid choice. Please enter a number from 1-7.")
        except KeyboardInterrupt:
            print("\n\n🚪 Goodbye!")
            sys.exit(0)
        except EOFError:
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

        # Pause before showing menu again
        input("\nPress Enter to continue...")
        print("\n" + "="*80)


if __name__ == "__main__":
    main()
