"""
CloudTrail and Logging Setup
============================
Sets up AWS logging infrastructure for SOC monitoring.

CREATES:
1. CloudTrail for API logging
2. CloudWatch Log Groups
3. GuardDuty for threat detection
4. SNS topic for alerts
"""

import boto3
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def get_account_id():
    """Get current AWS account ID"""
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account']


def create_cloudtrail_bucket(s3_client, account_id):
    """Create S3 bucket for CloudTrail logs"""
    bucket_name = config.S3_CLOUDTRAIL_BUCKET
    console.print(f"\n[bold cyan]Creating CloudTrail log bucket:[/] {bucket_name}")
    
    try:
        if config.AWS_REGION == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': config.AWS_REGION}
            )
        
        # CloudTrail bucket policy
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSCloudTrailAclCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket_name}"
                },
                {
                    "Sid": "AWSCloudTrailWrite",
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                    "Condition": {
                        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                    }
                }
            ]
        }
        
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
        
        # Enable encryption
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
            }
        )
        
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [
                {'Key': 'Purpose', 'Value': 'cloudtrail-logs'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]}
        )
        
        console.print(f"  [green]✓[/] Bucket created with CloudTrail permissions")
        return bucket_name
        
    except s3_client.exceptions.BucketAlreadyOwnedByYou:
        console.print(f"  [yellow]! Bucket already exists[/]")
        return bucket_name
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def create_cloudtrail(cloudtrail_client, bucket_name):
    """Create CloudTrail for API logging"""
    trail_name = config.CLOUDTRAIL_NAME
    console.print(f"\n[bold cyan]Creating CloudTrail:[/] {trail_name}")
    
    try:
        cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
            TagsList=[
                # {'Key': 'Purpose', 'Value': 'security-monitoring'}, # Duplicate key
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]
        )
        
        # Start logging
        cloudtrail_client.start_logging(Name=trail_name)
        
        console.print(f"  [green]✓[/] CloudTrail created and logging started")
        console.print(f"  [dim]Logs will be stored in: s3://{bucket_name}/[/]")
        return trail_name
        
    except cloudtrail_client.exceptions.TrailAlreadyExistsException:
        console.print(f"  [yellow]! Trail already exists[/]")
        return trail_name
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def create_cloudwatch_log_group(logs_client):
    """Create CloudWatch Log Group for centralized logging"""
    log_group = config.CLOUDWATCH_LOG_GROUP
    console.print(f"\n[bold cyan]Creating CloudWatch Log Group:[/] {log_group}")
    
    try:
        logs_client.create_log_group(
            logGroupName=log_group,
            tags={
                # 'Purpose': 'security-lab-logs', # Duplicate key
                **config.COMMON_TAGS
            }
        )
        
        # Set retention to 7 days (for cost savings in lab)
        logs_client.put_retention_policy(
            logGroupName=log_group,
            retentionInDays=7
        )
        
        console.print(f"  [green]✓[/] Log group created with 7-day retention")
        return log_group
        
    except logs_client.exceptions.ResourceAlreadyExistsException:
        console.print(f"  [yellow]! Log group already exists[/]")
        return log_group
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def enable_guardduty(guardduty_client):
    """Enable GuardDuty for threat detection"""
    console.print(f"\n[bold cyan]Enabling GuardDuty[/]")
    
    try:
        response = guardduty_client.create_detector(
            Enable=True,
            FindingPublishingFrequency='FIFTEEN_MINUTES',
            Tags={
                'Purpose': 'threat-detection',
                **config.COMMON_TAGS
            }
        )
        
        detector_id = response['DetectorId']
        console.print(f"  [green]✓[/] GuardDuty enabled")
        console.print(f"  [dim]Detector ID: {detector_id}[/]")
        return detector_id
        
    except guardduty_client.exceptions.BadRequestException as e:
        error_msg = str(e).lower()
        if 'already enabled' in error_msg or 'already exists' in error_msg:
            # Get existing detector
            detectors = guardduty_client.list_detectors()
            if detectors['DetectorIds']:
                console.print(f"  [yellow]! GuardDuty already enabled[/]")
                return detectors['DetectorIds'][0]
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def create_sns_topic(sns_client):
    """Create SNS topic for security alerts"""
    topic_name = f"{config.LAB_PREFIX}-security-alerts"
    console.print(f"\n[bold cyan]Creating SNS Alert Topic:[/] {topic_name}")
    
    try:
        response = sns_client.create_topic(
            Name=topic_name,
            Tags=[
                # {'Key': 'Purpose', 'Value': 'security-alerts'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]
        )
        
        topic_arn = response['TopicArn']
        console.print(f"  [green]✓[/] SNS topic created")
        console.print(f"  [dim]Topic ARN: {topic_arn}[/]")
        console.print(f"  [yellow]! Subscribe your email to receive alerts[/]")
        return topic_arn
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def display_summary(resources):
    """Display summary of created logging resources"""
    table = Table(title="Logging & Detection Resources")
    table.add_column("Service", style="cyan")
    table.add_column("Resource", style="green")
    table.add_column("Purpose", style="yellow")
    
    if resources.get('cloudtrail_bucket'):
        table.add_row("S3", resources['cloudtrail_bucket'], "CloudTrail log storage")
    if resources.get('cloudtrail'):
        table.add_row("CloudTrail", resources['cloudtrail'], "API activity logging")
    if resources.get('log_group'):
        table.add_row("CloudWatch", resources['log_group'], "Centralized logs")
    if resources.get('guardduty'):
        table.add_row("GuardDuty", resources['guardduty'], "Threat detection")
    if resources.get('sns_topic'):
        table.add_row("SNS", resources['sns_topic'], "Security alerts")
    
    console.print("\n")
    console.print(table)


def main():
    console.print(Panel.fit(
        "[bold cyan]📊 LOGGING & DETECTION SETUP 📊[/]\n"
        "This script sets up AWS security monitoring.\n"
        "[green]These are defensive security controls.[/]",
        title="AWS Security Lab"
    ))
    
    # Create clients
    s3_client = boto3.client('s3', region_name=config.AWS_REGION)
    cloudtrail_client = boto3.client('cloudtrail', region_name=config.AWS_REGION)
    logs_client = boto3.client('logs', region_name=config.AWS_REGION)
    guardduty_client = boto3.client('guardduty', region_name=config.AWS_REGION)
    sns_client = boto3.client('sns', region_name=config.AWS_REGION)
    
    account_id = get_account_id()
    console.print(f"\n[dim]AWS Account ID: {account_id}[/]")
    
    resources = {}
    
    # Create logging infrastructure
    resources['cloudtrail_bucket'] = create_cloudtrail_bucket(s3_client, account_id)
    
    if resources['cloudtrail_bucket']:
        resources['cloudtrail'] = create_cloudtrail(cloudtrail_client, resources['cloudtrail_bucket'])
    
    resources['log_group'] = create_cloudwatch_log_group(logs_client)
    resources['guardduty'] = enable_guardduty(guardduty_client)
    resources['sns_topic'] = create_sns_topic(sns_client)
    
    display_summary(resources)
    
    console.print("\n[bold green]Logging setup complete![/]")
    console.print("Monitor security events in: [cyan]soc-defense/log-analysis/[/]")


if __name__ == "__main__":
    main()
