"""
Auto-Remediation Tool
=====================
Automated security response tool that fixes vulnerabilities detected in the lab.

REMEDIATION ACTIONS:
1. S3: Enable encryption, versioning, block public access
2. IAM: Detach dangerous policies, remove overprivileged users
3. EC2: Revoke open security group rules, enforce IMDSv2
"""

import boto3
import json
import sys
import os
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich.progress import Progress

console = Console()

class AutoRemediator:
    """Automated remediation for detected vulnerabilities"""
    
    def __init__(self, dry_run=False):
        self.dry_run = dry_run
        self.region = config.AWS_REGION
        self.s3 = boto3.client('s3', region_name=self.region)
        self.iam = boto3.client('iam', region_name=self.region)
        self.ec2 = boto3.client('ec2', region_name=self.region)
        
    def remediate_s3_bucket(self, bucket_name):
        """Secure a vulnerable S3 bucket"""
        console.print(f"\n[cyan]Checking Bucket:[/] {bucket_name}")
        
        try:
            # Check existence
            self.s3.head_bucket(Bucket=bucket_name)
        except:
            console.print(f"  [dim]Bucket not found[/]")
            return

        actions = []
        
        # 1. Block Public Access
        console.print("  [dim]• Enforcing Public Access Block[/]")
        if not self.dry_run:
            try:
                self.s3.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                actions.append("Enabled Public Access Block")
            except Exception as e:
                console.print(f"    [red]Error:[/] {e}")
        else:
            actions.append("[DRY RUN] Would enable Public Access Block")

        # 2. Enable Encryption
        console.print("  [dim]• Enabling Server-Side Encryption[/]")
        if not self.dry_run:
            try:
                self.s3.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
                    }
                )
                actions.append("Enabled AES256 Encryption")
            except Exception as e:
                console.print(f"    [red]Error:[/] {e}")
        else:
            actions.append("[DRY RUN] Would enable Encryption")

        # 3. Enable Versioning
        console.print("  [dim]• Enabling Versioning[/]")
        if not self.dry_run:
            try:
                self.s3.put_bucket_versioning(
                    Bucket=bucket_name,
                    VersioningConfiguration={'Status': 'Enabled'}
                )
                actions.append("Enabled Versioning")
            except Exception as e:
                console.print(f"    [red]Error:[/] {e}")
        else:
            actions.append("[DRY RUN] Would enable Versioning")
            
        # 4. Remove Public Policy
        console.print("  [dim]• Checking/Removing Bucket Policy[/]")
        if not self.dry_run:
            try:
                self.s3.delete_bucket_policy(Bucket=bucket_name)
                actions.append("Removed potentially dangerous bucket policy")
            except Exception as e:
                # Often throws error if no policy exists, which is fine
                pass
        
        # Summary
        for action in actions:
            console.print(f"  [green]✓[/] {action}")

    def remediate_iam_user(self, user_name):
        """Secure a vulnerable IAM user"""
        console.print(f"\n[cyan]Checking IAM User:[/] {user_name}")
        
        try:
            self.iam.get_user(UserName=user_name)
        except:
            console.print("  [dim]User not found[/]")
            return
            
        actions = []
        
        # Detach all managed policies
        paginator = self.iam.get_paginator('list_attached_user_policies')
        for page in paginator.paginate(UserName=user_name):
            for policy in page['AttachedPolicies']:
                if not self.dry_run:
                    self.iam.detach_user_policy(UserName=user_name, PolicyArn=policy['PolicyArn'])
                    actions.append(f"Detached policy: {policy['PolicyName']}")
                else:
                    actions.append(f"[DRY RUN] Would detach: {policy['PolicyName']}")
        
        # Delete inline policies
        try:
            inline = self.iam.list_user_policies(UserName=user_name)
            for policy_name in inline['PolicyNames']:
                if not self.dry_run:
                    self.iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                    actions.append(f"Deleted inline policy: {policy_name}")
                else:
                    actions.append(f"[DRY RUN] Would delete inline policy: {policy_name}")
        except Exception as e:
            console.print(f"  [red]Error checking inline policies:[/] {e}")
            
        # Summary
        if actions:
            for action in actions:
                console.print(f"  [green]✓[/] {action}")
        else:
            console.print(f"  [green]✓[/] User has no dangerous policies attached")

    def remediate_ec2_sg(self, sg_id):
        """Fix vulnerable security group"""
        console.print(f"\n[cyan]Checking Security Group:[/] {sg_id}")
        
        try:
            sg = self.ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        except:
            console.print("  [dim]Security Group not found[/]")
            return
            
        actions = []
        
        # Check permissions
        for perm in sg.get('IpPermissions', []):
            # Look for 0.0.0.0/0
            is_open_world = False
            for r in perm.get('IpRanges', []):
                if r.get('CidrIp') == '0.0.0.0/0':
                    is_open_world = True
                    break
            
            if is_open_world:
                description = f"Rule: Protocol {perm.get('IpProtocol')} Port {perm.get('FromPort')}-{perm.get('ToPort')}"
                if not self.dry_run:
                    try:
                        self.ec2.revoke_security_group_ingress(
                            GroupId=sg_id,
                            IpPermissions=[perm]
                        )
                        actions.append(f"Revoked open world access - {description}")
                    except Exception as e:
                        console.print(f"  [red]Error revoking rule:[/] {e}")
                else:
                    actions.append(f"[DRY RUN] Would revoke open world access - {description}")

        if actions:
            for action in actions:
                console.print(f"  [green]✓[/] {action}")
        else:
            console.print("  [green]✓[/] No open-to-world rules found")

    def run(self):
        console.print(Panel.fit(
            f"[bold green]🛡️ AUTO-REMEDIATION TOOL 🛡️[/]\n"
            f"Mode: {'[yellow]DRY RUN[/]' if self.dry_run else '[red]ACTIVE REMEDIATION[/]'}\n"
            "Scanning and fixing security issues...",
            title="SOC Defense"
        ))
        
        # 1. Remediate S3
        console.print("\n[bold]Phase 1: S3 Buckets[/]")
        buckets = [
            config.S3_PUBLIC_BUCKET,
            config.S3_UNENCRYPTED_BUCKET,
            config.S3_NO_VERSIONING_BUCKET,
            config.S3_CORS_BUCKET
        ]
        for bucket in buckets:
            self.remediate_s3_bucket(bucket)
            
        # 2. Remediate IAM
        console.print("\n[bold]Phase 2: IAM Entities[/]")
        users = [
            config.IAM_OVERPRIVILEGED_USER,
            config.IAM_ESCALATION_USER
        ]
        for user in users:
            self.remediate_iam_user(user)
            
        # 3. Remediate EC2
        console.print("\n[bold]Phase 3: EC2 Security[/]")
        # Find vulnerable SG ID dynamically
        try:
            sgs = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': [config.EC2_VULNERABLE_SG]}]
            )
            if sgs['SecurityGroups']:
                self.remediate_ec2_sg(sgs['SecurityGroups'][0]['GroupId'])
            else:
                console.print(f"  [dim]Security Group {config.EC2_VULNERABLE_SG} not found[/]")
        except Exception as e:
            console.print(f"  [red]Error finding security group:[/] {e}")
            
        console.print("\n[bold green]Remediation Complete![/]")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Auto Remediate Vulnerabilities')
    parser.add_argument('--dry-run', action='store_true', help='Simulate changes without applying them')
    args = parser.parse_args()
    
    # Prompt for confirmation if not dry run
    if not args.dry_run:
        if not Confirm.ask("[bold red]WARNING: This will modify AWS resources. Proceed?[/]"):
            return

    remediator = AutoRemediator(dry_run=args.dry_run)
    remediator.run()

if __name__ == '__main__':
    main()
