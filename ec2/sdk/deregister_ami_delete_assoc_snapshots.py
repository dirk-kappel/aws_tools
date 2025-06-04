#!/usr/bin/env python3
"""
AWS AMI Cleanup Script.

This script safely deregisters an AMI and deletes its associated snapshots
with detailed confirmation steps to prevent accidental deletions.
"""

import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


class AMICleanup:
    def __init__(self, region_name: str | None = None):
        """Initialize the AMI cleanup utility."""
        try:
            self.ec2_client = boto3.client("ec2", region_name=region_name)
            self.region = region_name or boto3.Session().region_name or "us-east-1"
            print(f"✓ Connected to AWS EC2 in region: {self.region}")
        except NoCredentialsError:
            print("❌ Error: AWS credentials not found. Please configure your credentials.")
            sys.exit(1)
        except (ClientError, ValueError) as e:
            print(f"❌ Error initializing AWS client: {e}")
            sys.exit(1)

    def get_ami_details(self, ami_id: str) -> dict[str, Any]:
        """Retrieve detailed information about the AMI."""
        try:
            response = self.ec2_client.describe_images(ImageIds=[ami_id])
            if not response["Images"]:
                msg = f"AMI {ami_id} not found"
                raise ValueError(msg)
            return response["Images"][0]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidAMIID.NotFound":
                msg = f"AMI {ami_id} not found"
                raise ValueError(msg) from e
            raise

    def get_snapshot_details(self, snapshot_ids: list[str]) -> list[dict[str, Any]]:
        """Retrieve detailed information about snapshots."""
        if not snapshot_ids:
            return []

        try:
            response = self.ec2_client.describe_snapshots(SnapshotIds=snapshot_ids)
            return response["Snapshots"]
        except ClientError as e:
            print(f"⚠️  Warning: Error retrieving some snapshot details: {e}")
            return []

    def extract_snapshot_ids(self, ami_details: dict[str, Any]) -> list[str]:
        """Extract snapshot IDs from AMI block device mappings."""
        snapshot_ids = []
        for block_device in ami_details.get("BlockDeviceMappings", []):
            if "Ebs" in block_device and "SnapshotId" in block_device["Ebs"]:
                snapshot_ids.append(block_device["Ebs"]["SnapshotId"])
        return snapshot_ids

    def format_tags(self, tags: list[dict[str, str]]) -> str:
        """Format tags for display."""
        if not tags:
            return "No tags"
        return "\n".join([f"    {tag['Key']}: {tag['Value']}" for tag in tags])

    def display_ami_info(self, ami_details: dict[str, Any]) -> None:
        """Display AMI information in a readable format."""
        print("\n" + "="*80)
        print("AMI INFORMATION")
        print("="*80)
        print(f"AMI ID: {ami_details['ImageId']}")
        print(f"Name: {ami_details.get('Name', 'N/A')}")
        print(f"Description: {ami_details.get('Description', 'N/A')}")
        print(f"State: {ami_details.get('State', 'N/A')}")
        print(f"Owner: {ami_details.get('OwnerId', 'N/A')}")
        print(f"Architecture: {ami_details.get('Architecture', 'N/A')}")
        print(f"Creation Date: {ami_details.get('CreationDate', 'N/A')}")
        print(f"Public: {ami_details.get('Public', False)}")
        print(f"Root Device Type: {ami_details.get('RootDeviceType', 'N/A')}")
        print(f"Virtualization Type: {ami_details.get('VirtualizationType', 'N/A')}")
        print("\nTags:")
        print(self.format_tags(ami_details.get("Tags", [])))

    def display_snapshot_info(self, snapshots: list[dict[str, Any]]) -> None:
        """Display snapshot information in a readable format."""
        if not snapshots:
            print("\n" + "="*80)
            print("ASSOCIATED SNAPSHOTS")
            print("="*80)
            print("No snapshots found associated with this AMI.")
            return

        print("\n" + "="*80)
        print("ASSOCIATED SNAPSHOTS")
        print("="*80)

        for i, snapshot in enumerate(snapshots, 1):
            print(f"\n--- Snapshot {i} ---")
            print(f"Snapshot ID: {snapshot['SnapshotId']}")
            print(f"Description: {snapshot.get('Description', 'N/A')}")
            print(f"Volume Size: {snapshot.get('VolumeSize', 'N/A')} GB")
            print(f"State: {snapshot.get('State', 'N/A')}")
            print(f"Owner: {snapshot.get('OwnerId', 'N/A')}")
            print(f"Start Time: {snapshot.get('StartTime', 'N/A')}")
            print(f"Progress: {snapshot.get('Progress', 'N/A')}")
            print(f"Encrypted: {snapshot.get('Encrypted', False)}")
            print("Tags:")
            print(self.format_tags(snapshot.get("Tags", [])))

    def confirm_action(self, prompt: str) -> bool:
        """Get user confirmation for an action."""
        while True:
            response = input(f"\n{prompt} (yes/no): ").lower().strip()
            if response in ["yes", "y"]:
                return True
            if response in ["no", "n"]:
                return False
            print("Please enter 'yes' or 'no'")

    def deregister_ami(self, ami_id: str) -> None:
        """Deregister the AMI."""
        try:
            print(f"\n🔄 Deregistering AMI {ami_id}...")
            self.ec2_client.deregister_image(ImageId=ami_id)
            print(f"✓ Successfully deregistered AMI {ami_id}")
        except ClientError as e:
            print(f"❌ Error deregistering AMI {ami_id}: {e}")
            raise

    def _delete_single_snapshot(self, snapshot_id: str) -> tuple[bool, str | None]:
        """Delete a single snapshot and return success status and error message."""
        try:
            self.ec2_client.delete_snapshot(SnapshotId=snapshot_id)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "InvalidSnapshot.NotFound":
                return True, f"Snapshot {snapshot_id} not found (already deleted)"
            return False, str(e)
        else:
            return True, None

    def delete_snapshots(self, snapshot_ids: list[str]) -> None:
        """Delete the specified snapshots."""
        if not snapshot_ids:
            print("No snapshots to delete.")
            return

        for snapshot_id in snapshot_ids:
            print(f"🔄 Deleting snapshot {snapshot_id}...")
            success, error_msg = self._delete_single_snapshot(snapshot_id)

            if success:
                if error_msg:
                    print(f"⚠️  {error_msg}")
                else:
                    print(f"✓ Successfully deleted snapshot {snapshot_id}")
            else:
                print(f"❌ Error deleting snapshot {snapshot_id}: {error_msg}")
                raise ClientError(
                    error_response={"Error": {"Code": "DeleteSnapshotFailed", "Message": error_msg}},
                    operation_name="DeleteSnapshot",
                )

    def cleanup_ami(self, ami_id: str) -> None:
        """Main method to cleanup AMI and associated snapshots."""
        print(f"\n🔍 Gathering information for AMI: {ami_id}")

        # Get AMI details
        try:
            ami_details = self.get_ami_details(ami_id)
        except ValueError as e:
            print(f"❌ {e}")
            return
        except ClientError as e:
            print(f"❌ Error retrieving AMI details: {e}")
            return

        # Extract snapshot IDs
        snapshot_ids = self.extract_snapshot_ids(ami_details)

        # Get snapshot details
        snapshots = self.get_snapshot_details(snapshot_ids)

        # Display all information
        self.display_ami_info(ami_details)
        self.display_snapshot_info(snapshots)

        # Summary
        print("\n" + "="*80)
        print("CLEANUP SUMMARY")
        print("="*80)
        print(f"AMI to deregister: {ami_id}")
        print(f"Snapshots to delete: {len(snapshot_ids)}")
        if snapshot_ids:
            for snapshot_id in snapshot_ids:
                print(f"  - {snapshot_id}")

        # Get confirmations
        if not self.confirm_action("⚠️  Do you want to proceed with deregistering this AMI and deleting the associated snapshots?"):
            print("❌ AMI deregistration and Snapshot deletion cancelled.")
            return

        # Perform cleanup
        try:
            self.deregister_ami(ami_id)
            if snapshot_ids:
                self.delete_snapshots(snapshot_ids)
            print("\n✅ Cleanup completed successfully!")
        except ClientError as e:
            print(f"\n❌ Cleanup failed: {e}")
            sys.exit(1)


def main():
    """Main function."""
    print("AWS AMI Cleanup Tool")
    print("This tool will safely deregister an AMI and delete its associated snapshots.")
    print("You will be shown detailed information before any destructive operations.")

    # Get region
    default_region = boto3.Session().region_name

    if default_region:
        # There's a default region, allow user to use it or specify a different one
        region = input(f"\nEnter AWS region (press Enter for default: {default_region}): ").strip()
        if not region:
            region = default_region
    else:
        # No default region, require user input
        print("\n❌ No default AWS region found in environment/profile.")
        while True:
            region = input("Please enter AWS region (required): ").strip()
            if region:
                break
            print("❌ Region is required. Please enter a valid AWS region.")

    print(f"Using region: {region}")

    # Initialize cleanup tool
    cleanup_tool = AMICleanup(region_name=region)

    while True:
        # Get AMI ID from user
        print("\n" + "-"*50)
        ami_id = input("Enter AMI ID to cleanup (or 'quit' to exit): ").strip()

        if ami_id.lower() in ["quit", "exit", "q"]:
            print("👋 Goodbye!")
            break

        if not ami_id:
            print("❌ Please enter a valid AMI ID.")
            continue

        if not ami_id.startswith("ami-"):
            print("❌ AMI ID should start with 'ami-'")
            continue

        # Perform cleanup
        cleanup_tool.cleanup_ami(ami_id)

        # Ask if user wants to continue
        if not cleanup_tool.confirm_action("Do you want to cleanup another AMI?"):
            print("👋 Goodbye!")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Operation cancelled by user. Goodbye!")
        sys.exit(0)
    except (ClientError, ValueError) as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
