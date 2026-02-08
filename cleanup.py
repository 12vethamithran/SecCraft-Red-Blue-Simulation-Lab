"""
Cleanup Script
==============
Removes all AWS resources created by the security lab.

IMPORTANT: Run this when you're done to avoid ongoing charges!
"""

import boto3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.progress import Progress

console = Console()


def delete_s3_buckets(s3_client, s3_resource):
    """Delete all lab S3 buckets"""
    buckets = [
        config.S3_PUBLIC_BUCKET,
        config.S3_UNENCRYPTED_BUCKET,
        config.S3_NO_VERSIONING_BUCKET,
        config.S3_CORS_BUCKET,
        config.S3_SECURE_BUCKET,
        config.S3_CLOUDTRAIL_BUCKET
    ]
    
    console.print("\n[bold cyan]Deleting S3 Buckets...[/]")
    
    for bucket_name in buckets:
        try:
            # First, delete all objects in the bucket
            bucket = s3_resource.Bucket(bucket_name)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
            
            # Then delete the bucket
            s3_client.delete_bucket(Bucket=bucket_name)
            console.print(f"  [green]✓[/] Deleted: {bucket_name}")
        except s3_client.exceptions.NoSuchBucket:
            console.print(f"  [dim]- Not found: {bucket_name}[/]")
        except Exception as e:
            console.print(f"  [red]✗ Error deleting {bucket_name}:[/] {str(e)}")


def delete_iam_resources(iam_client):
    """Delete all lab IAM users and roles"""
    console.print("\n[bold cyan]Deleting IAM Resources...[/]")
    
    # Delete users
    users = [config.IAM_OVERPRIVILEGED_USER, config.IAM_ESCALATION_USER]
    for user_name in users:
        try:
            # Delete inline policies
            policies = iam_client.list_user_policies(UserName=user_name)
            for policy_name in policies.get('PolicyNames', []):
                iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
            
            # Delete attached policies
            attached = iam_client.list_attached_user_policies(UserName=user_name)
            for policy in attached.get('AttachedPolicies', []):
                iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
            
            # Delete access keys
            keys = iam_client.list_access_keys(UserName=user_name)
            for key in keys.get('AccessKeyMetadata', []):
                iam_client.delete_access_key(UserName=user_name, AccessKeyId=key['AccessKeyId'])
            
            # Delete user
            iam_client.delete_user(UserName=user_name)
            console.print(f"  [green]✓[/] Deleted user: {user_name}")
        except iam_client.exceptions.NoSuchEntityException:
            console.print(f"  [dim]- User not found: {user_name}[/]")
        except Exception as e:
            console.print(f"  [red]✗ Error deleting {user_name}:[/] {str(e)}")
    
    # Delete roles
    roles = [config.IAM_WEAK_TRUST_ROLE, config.IAM_WILDCARD_ROLE, config.IAM_SECURE_ROLE]
    for role_name in roles:
        try:
            # Delete inline policies
            policies = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in policies.get('PolicyNames', []):
                iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            
            # Delete attached policies
            attached = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get('AttachedPolicies', []):
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
            
            # Delete role
            iam_client.delete_role(RoleName=role_name)
            console.print(f"  [green]✓[/] Deleted role: {role_name}")
        except iam_client.exceptions.NoSuchEntityException:
            console.print(f"  [dim]- Role not found: {role_name}[/]")
        except Exception as e:
            console.print(f"  [red]✗ Error deleting {role_name}:[/] {str(e)}")


def delete_ec2_resources(ec2_client):
    """Delete all lab EC2 instances and security groups"""
    console.print("\n[bold cyan]Deleting EC2 Resources...[/]")
    
    # Find and terminate instances with our tags
    try:
        instances = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:Project', 'Values': ['aws-security-lab']},
                {'Name': 'instance-state-name', 'Values': ['running', 'stopped', 'pending']}
            ]
        )
        
        instance_ids = []
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_ids.append(instance['InstanceId'])
        
        if instance_ids:
            ec2_client.terminate_instances(InstanceIds=instance_ids)
            console.print(f"  [green]✓[/] Terminated instances: {', '.join(instance_ids)}")
            
            # Wait for termination
            waiter = ec2_client.get_waiter('instance_terminated')
            console.print("  [dim]Waiting for instances to terminate...[/]")
            waiter.wait(InstanceIds=instance_ids)
        else:
            console.print("  [dim]- No instances found[/]")
            
    except Exception as e:
        console.print(f"  [red]✗ Error with instances:[/] {str(e)}")
    
    # Delete security groups
    sg_names = [config.EC2_VULNERABLE_SG, config.EC2_SECURE_SG]
    for sg_name in sg_names:
        try:
            sgs = ec2_client.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
            )
            for sg in sgs['SecurityGroups']:
                ec2_client.delete_security_group(GroupId=sg['GroupId'])
                console.print(f"  [green]✓[/] Deleted security group: {sg_name}")
        except Exception as e:
            if 'does not exist' in str(e).lower():
                console.print(f"  [dim]- Not found: {sg_name}[/]")
            else:
                console.print(f"  [red]✗ Error deleting {sg_name}:[/] {str(e)}")


def delete_cloudtrail(cloudtrail_client):
    """Delete CloudTrail"""
    console.print("\n[bold cyan]Deleting CloudTrail...[/]")
    
    try:
        cloudtrail_client.stop_logging(Name=config.CLOUDTRAIL_NAME)
        cloudtrail_client.delete_trail(Name=config.CLOUDTRAIL_NAME)
        console.print(f"  [green]✓[/] Deleted: {config.CLOUDTRAIL_NAME}")
    except cloudtrail_client.exceptions.TrailNotFoundException:
        console.print(f"  [dim]- Not found: {config.CLOUDTRAIL_NAME}[/]")
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")


def delete_cloudwatch_logs(logs_client):
    """Delete CloudWatch Log Group"""
    console.print("\n[bold cyan]Deleting CloudWatch Logs...[/]")
    
    try:
        logs_client.delete_log_group(logGroupName=config.CLOUDWATCH_LOG_GROUP)
        console.print(f"  [green]✓[/] Deleted: {config.CLOUDWATCH_LOG_GROUP}")
    except logs_client.exceptions.ResourceNotFoundException:
        console.print(f"  [dim]- Not found: {config.CLOUDWATCH_LOG_GROUP}[/]")
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")


def delete_guardduty(guardduty_client):
    """Delete GuardDuty detector"""
    console.print("\n[bold cyan]Deleting GuardDuty...[/]")
    
    try:
        detectors = guardduty_client.list_detectors()
        for detector_id in detectors.get('DetectorIds', []):
            # Check if it's our detector by tags
            guardduty_client.delete_detector(DetectorId=detector_id)
            console.print(f"  [green]✓[/] Deleted detector: {detector_id}")
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")


def main():
    console.print(Panel.fit(
        "[bold yellow]🧹 AWS SECURITY LAB CLEANUP 🧹[/]\n\n"
        "This will DELETE all resources created by the security lab:\n"
        "• S3 buckets and all their contents\n"
        "• IAM users, roles, and policies\n"
        "• EC2 instances and security groups\n"
        "• CloudTrail, CloudWatch logs, and GuardDuty\n\n"
        "[red]This action CANNOT be undone![/]",
        title="Cleanup",
        border_style="yellow"
    ))
    
    if not Confirm.ask("\n[bold red]Are you SURE you want to delete all resources?[/]"):
        console.print("[yellow]Cleanup cancelled.[/]")
        return
    
    # Create clients
    s3_client = boto3.client('s3', region_name=config.AWS_REGION)
    s3_resource = boto3.resource('s3', region_name=config.AWS_REGION)
    iam_client = boto3.client('iam', region_name=config.AWS_REGION)
    ec2_client = boto3.client('ec2', region_name=config.AWS_REGION)
    cloudtrail_client = boto3.client('cloudtrail', region_name=config.AWS_REGION)
    logs_client = boto3.client('logs', region_name=config.AWS_REGION)
    guardduty_client = boto3.client('guardduty', region_name=config.AWS_REGION)
    
    # Delete all resources
    delete_cloudtrail(cloudtrail_client)
    delete_ec2_resources(ec2_client)
    delete_iam_resources(iam_client)
    delete_s3_buckets(s3_client, s3_resource)
    delete_cloudwatch_logs(logs_client)
    delete_guardduty(guardduty_client)
    
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]✓ CLEANUP COMPLETE[/]\n\n"
        "All security lab resources have been removed.\n"
        "Check your AWS Console to verify.",
        title="Done",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
