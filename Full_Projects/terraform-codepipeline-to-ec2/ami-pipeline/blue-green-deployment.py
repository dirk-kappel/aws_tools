import json
import logging
import time

import boto3

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
ec2 = boto3.client('ec2')
autoscaling = boto3.client('autoscaling')
elbv2 = boto3.client('elbv2')
codepipeline = boto3.client('codepipeline')

def lambda_handler(event, context):
    """
    Performs blue-green deployment by:
    1. Creating new Launch Template version with new AMI
    2. Creating new Auto Scaling Group (Green)
    3. Switching Load Balancer to point to Green ASG
    4. Terminating old Auto Scaling Group (Blue)
    """
    
    try:
        # Get input parameters from CodePipeline
        job_id = event['CodePipeline.job']['id']
        input_artifacts = event['CodePipeline.job']['data']['inputArtifacts']
        
        # Extract AMI ID from build artifacts
        ami_id = extract_ami_id_from_artifacts(input_artifacts)
        logger.info(f"Deploying with AMI ID: {ami_id}")
        
        # Configuration
        project_name = "codepipeline-learning"
        launch_template_name = f"{project_name}-lt"
        target_group_name = f"{project_name}-tg"
        old_asg_name = f"{project_name}-asg"
        new_asg_name = f"{project_name}-asg-green"
        
        # Step 1: Create new Launch Template version
        logger.info("Step 1: Creating new Launch Template version")
        create_new_launch_template_version(launch_template_name, ami_id)
        
        # Step 2: Create Green Auto Scaling Group
        logger.info("Step 2: Creating Green Auto Scaling Group")
        create_green_asg(old_asg_name, new_asg_name, launch_template_name)
        
        # Step 3: Wait for instances to be healthy
        logger.info("Step 3: Waiting for Green instances to be healthy")
        wait_for_healthy_instances(new_asg_name)
        
        # Step 4: Switch traffic to Green ASG
        logger.info("Step 4: Switching traffic to Green ASG")
        switch_traffic_to_green(target_group_name, new_asg_name)
        
        # Step 5: Wait for traffic switch to complete
        logger.info("Step 5: Waiting for traffic switch to complete")
        time.sleep(60)  # Allow time for connections to drain
        
        # Step 6: Terminate Blue ASG
        logger.info("Step 6: Terminating Blue ASG")
        terminate_blue_asg(old_asg_name)
        
        # Step 7: Rename Green ASG to primary name
        logger.info("Step 7: Renaming Green ASG to primary name")
        rename_asg(new_asg_name, old_asg_name)
        
        # Success - notify CodePipeline
        codepipeline.put_job_success_result(jobId=job_id)
        logger.info("Blue-Green deployment completed successfully!")
        
        return {
            'statusCode': 200,
            'body': json.dumps('Blue-Green deployment completed successfully!')
        }
        
    except Exception as e:
        logger.error(f"Deployment failed: {str(e)}")
        codepipeline.put_job_failure_result(
            jobId=job_id,
            failureDetails={'message': str(e), 'type': 'JobFailed'}
        )
        raise e

def extract_ami_id_from_artifacts(input_artifacts):
    """Extract AMI ID from CodePipeline input artifacts"""
    # This would need to be implemented based on how artifacts are structured
    # For now, return a placeholder - in real implementation, you'd extract from S3
    # This is a simplified version for the learning project
    return "ami-placeholder"

def create_new_launch_template_version(template_name, ami_id):
    """Create new version of Launch Template with new AMI"""
    
    # Get current launch template
    response = ec2.describe_launch_templates(
        LaunchTemplateNames=[template_name]
    )
    template_id = response['LaunchTemplates'][0]['LaunchTemplateId']
    
    # Get latest version to copy settings
    latest_version = ec2.describe_launch_template_versions(
        LaunchTemplateId=template_id,
        Versions=['$Latest']
    )
    
    latest_data = latest_version['LaunchTemplateVersions'][0]['LaunchTemplateData']
    
    # Create new version with updated AMI
    latest_data['ImageId'] = ami_id
    
    ec2.create_launch_template_version(
        LaunchTemplateId=template_id,
        LaunchTemplateData=latest_data,
        VersionDescription=f"Updated AMI: {ami_id}"
    )
    logger.info(f"Created new launch template version with AMI {ami_id}")

def create_green_asg(old_asg_name, new_asg_name, launch_template_name):
    """Create Green Auto Scaling Group based on Blue ASG configuration"""
    
    # Get Blue ASG configuration
    response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[old_asg_name]
    )
    blue_asg = response['AutoScalingGroups'][0]
    
    # Create Green ASG with same configuration but new launch template
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=new_asg_name,
        LaunchTemplate={
            'LaunchTemplateName': launch_template_name,
            'Version': '$Latest'
        },
        MinSize=blue_asg['MinSize'],
        MaxSize=blue_asg['MaxSize'],
        DesiredCapacity=blue_asg['DesiredCapacity'],
        VPCZoneIdentifier=blue_asg['VPCZoneIdentifier'],
        HealthCheckType=blue_asg['HealthCheckType'],
        HealthCheckGracePeriod=blue_asg['HealthCheckGracePeriod'],
        Tags=[
            {
                'Key': 'Name',
                'Value': f"{new_asg_name}",
                'PropagateAtLaunch': False,
                'ResourceId': new_asg_name,
                'ResourceType': 'auto-scaling-group'
            }
        ]
    )
    logger.info(f"Created Green ASG: {new_asg_name}")

def wait_for_healthy_instances(asg_name):
    """Wait for instances in ASG to be healthy"""
    max_wait_time = 600  # 10 minutes
    wait_time = 0
    
    while wait_time < max_wait_time:
        response = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )
        
        asg = response['AutoScalingGroups'][0]
        healthy_instances = 0
        
        for instance in asg['Instances']:
            if instance['LifecycleState'] == 'InService' and instance['HealthStatus'] == 'Healthy':
                healthy_instances += 1
        
        if healthy_instances >= asg['DesiredCapacity']:
            logger.info(f"All instances in {asg_name} are healthy")
            return
        
        logger.info(f"Waiting for instances to be healthy: {healthy_instances}/{asg['DesiredCapacity']}")
        time.sleep(30)
        wait_time += 30
    
    raise Exception(f"Timeout waiting for healthy instances in {asg_name}")

def switch_traffic_to_green(target_group_name, green_asg_name):
    """Switch Load Balancer traffic to Green ASG"""
    
    # Get target group ARN
    response = elbv2.describe_target_groups(
        Names=[target_group_name]
    )
    target_group_arn = response['TargetGroups'][0]['TargetGroupArn']
    
    # Attach Green ASG to target group
    autoscaling.attach_load_balancer_target_groups(
        AutoScalingGroupName=green_asg_name,
        TargetGroupARNs=[target_group_arn]
    )
    logger.info(f"Attached {green_asg_name} to target group")

def terminate_blue_asg(blue_asg_name):
    """Terminate the Blue Auto Scaling Group"""
    
    # Detach from load balancer first
    response = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[blue_asg_name]
    )
    
    if response['AutoScalingGroups']:
        # Scale down to 0
        autoscaling.update_auto_scaling_group(
            AutoScalingGroupName=blue_asg_name,
            MinSize=0,
            DesiredCapacity=0
        )
        
        # Wait for instances to terminate
        time.sleep(120)
        
        # Delete ASG
        autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=blue_asg_name,
            ForceDelete=True
        )
        logger.info(f"Deleted Blue ASG: {blue_asg_name}")

def rename_asg(current_name, target_name):
    """Rename ASG by creating new one with target name and deleting old"""
    # Note: ASGs can't be renamed directly, so this is a simplified placeholder
    # In practice, you might use tags to track which ASG is "primary"
    logger.info(f"ASG deployment completed. Green ASG {current_name} is now serving traffic")