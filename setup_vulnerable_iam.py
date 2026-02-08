"""
Vulnerable IAM Setup
====================
Creates intentionally vulnerable IAM users, roles, and policies for security testing.

VULNERABILITIES CREATED:
1. Overly permissive user with admin-like access
2. User that can escalate their own privileges
3. Role with weak trust policy (any principal can assume)
4. Role with wildcard permissions

WARNING: These are intentionally insecure configurations for educational purposes only!
"""

import boto3
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def create_iam_client():
    """Create boto3 IAM client"""
    return boto3.client('iam', region_name=config.AWS_REGION)


def get_account_id():
    """Get current AWS account ID"""
    sts = boto3.client('sts')
    return sts.get_caller_identity()['Account']


def create_overprivileged_user(iam_client, account_id):
    """
    VULNERABILITY 1: Overly Permissive User
    ---------------------------------------
    Attack Vector: Privilege abuse, data exfiltration
    Risk: User has excessive permissions beyond their role
    """
    user_name = config.IAM_OVERPRIVILEGED_USER
    console.print(f"\n[bold red]Creating OVERPRIVILEGED user:[/] {user_name}")
    
    try:
        # Create user
        iam_client.create_user(
            UserName=user_name,
            Tags=[
                {'Key': 'Vulnerability', 'Value': 'excessive-permissions'},
                {'Key': 'Severity', 'Value': 'Critical'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]
        )
        
        # VULNERABLE: Extremely broad policy
        overprivileged_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3FullAccess",
                    "Effect": "Allow",
                    "Action": "s3:*",  # VULNERABLE: Full S3 access
                    "Resource": "*"
                },
                {
                    "Sid": "IAMDangerousActions",
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateUser",
                        "iam:CreateAccessKey",
                        "iam:AttachUserPolicy",  # VULNERABLE: Can escalate privileges
                        "iam:PutUserPolicy",
                        "iam:CreateRole",
                        "iam:AttachRolePolicy"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "EC2FullAccess",
                    "Effect": "Allow",
                    "Action": "ec2:*",  # VULNERABLE: Full EC2 access
                    "Resource": "*"
                },
                {
                    "Sid": "LambdaFullAccess",
                    "Effect": "Allow",
                    "Action": "lambda:*",  # VULNERABLE: Full Lambda access
                    "Resource": "*"
                }
            ]
        }
        
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName='overprivileged-policy',
            PolicyDocument=json.dumps(overprivileged_policy)
        )
        
        console.print(f"  [green]✓[/] Created with excessive permissions")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Can access S3, EC2, Lambda, and modify IAM")
        return True
        
    except iam_client.exceptions.EntityAlreadyExistsException:
        console.print(f"  [yellow]! User already exists[/]")
        return True
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_escalation_user(iam_client, account_id):
    """
    VULNERABILITY 2: Privilege Escalation Path
    ------------------------------------------
    Attack Vector: Self-escalation via policy attachment
    Risk: User can give themselves admin access
    """
    user_name = config.IAM_ESCALATION_USER
    console.print(f"\n[bold red]Creating ESCALATION user:[/] {user_name}")
    
    try:
        iam_client.create_user(
            UserName=user_name,
            Tags=[
                {'Key': 'Vulnerability', 'Value': 'privilege-escalation'},
                {'Key': 'Severity', 'Value': 'Critical'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]
        )
        
        # VULNERABLE: Can attach policies to self
        escalation_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ReadOnlyAccess",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket",
                        "ec2:Describe*"
                    ],
                    "Resource": "*"
                },
                {
                    # VULNERABLE: Can attach ANY policy to themselves
                    "Sid": "AttachPolicyToSelf",
                    "Effect": "Allow",
                    "Action": [
                        "iam:AttachUserPolicy",
                        "iam:PutUserPolicy"
                    ],
                    "Resource": f"arn:aws:iam::{account_id}:user/{user_name}"
                },
                {
                    # VULNERABLE: Can list all policies (reconnaissance)
                    "Sid": "ListPolicies",
                    "Effect": "Allow",
                    "Action": [
                        "iam:ListPolicies",
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:ListAttachedUserPolicies",
                        "iam:ListUserPolicies"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName='escalation-vulnerable-policy',
            PolicyDocument=json.dumps(escalation_policy)
        )
        
        console.print(f"  [green]✓[/] Created with self-escalation path")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Can attach AdministratorAccess to self")
        return True
        
    except iam_client.exceptions.EntityAlreadyExistsException:
        console.print(f"  [yellow]! User already exists[/]")
        return True
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_weak_trust_role(iam_client, account_id):
    """
    VULNERABILITY 3: Weak Trust Policy
    -----------------------------------
    Attack Vector: Cross-account access abuse
    Risk: Any AWS principal can assume this role
    """
    role_name = config.IAM_WEAK_TRUST_ROLE
    console.print(f"\n[bold red]Creating WEAK TRUST role:[/] {role_name}")
    
    try:
        # VULNERABLE: Any AWS principal can assume
        weak_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"  # VULNERABLE: Any AWS account
                    },
                    "Action": "sts:AssumeRole"
                    # Missing: Condition to restrict access
                }
            ]
        }
        
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(weak_trust_policy),
            Description='VULNERABLE: Any AWS principal can assume this role',
            Tags=[
                {'Key': 'Vulnerability', 'Value': 'weak-trust-policy'},
                {'Key': 'Severity', 'Value': 'Critical'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]
        )
        
        # Add some permissions to the role
        role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:*",
                        "ec2:*"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='weak-trust-role-policy',
            PolicyDocument=json.dumps(role_policy)
        )
        
        console.print(f"  [green]✓[/] Created with weak trust policy")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Any AWS account can assume this role")
        return True
        
    except iam_client.exceptions.EntityAlreadyExistsException:
        console.print(f"  [yellow]! Role already exists[/]")
        return True
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_wildcard_role(iam_client, account_id):
    """
    VULNERABILITY 4: Wildcard Permissions
    -------------------------------------
    Attack Vector: Unintended resource access
    Risk: Full access to all AWS services
    """
    role_name = config.IAM_WILDCARD_ROLE
    console.print(f"\n[bold red]Creating WILDCARD PERMISSIONS role:[/] {role_name}")
    
    try:
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='VULNERABLE: Wildcard permissions on all resources',
            Tags=[
                {'Key': 'Vulnerability', 'Value': 'wildcard-permissions'},
                {'Key': 'Severity', 'Value': 'Critical'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]
        )
        
        # VULNERABLE: Full admin-like access
        wildcard_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DangerousWildcard",
                    "Effect": "Allow",
                    "Action": "*",       # VULNERABLE: All actions
                    "Resource": "*"      # VULNERABLE: All resources
                }
            ]
        }
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='wildcard-dangerous-policy',
            PolicyDocument=json.dumps(wildcard_policy)
        )
        
        console.print(f"  [green]✓[/] Created with wildcard permissions")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Has Action:* Resource:* (full access)")
        return True
        
    except iam_client.exceptions.EntityAlreadyExistsException:
        console.print(f"  [yellow]! Role already exists[/]")
        return True
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_secure_role(iam_client, account_id):
    """
    SECURE REFERENCE ROLE
    ---------------------
    Demonstrates least-privilege IAM principles
    """
    role_name = config.IAM_SECURE_ROLE
    console.print(f"\n[bold green]Creating SECURE reference role:[/] {role_name}")
    
    try:
        # SECURE: Specific trust with conditions
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": account_id
                        }
                    }
                }
            ]
        }
        
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='SECURE: Least privilege role for reference',
            Tags=[
                {'Key': 'Vulnerability', 'Value': 'none'},
                {'Key': 'Purpose', 'Value': 'secure-reference'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]
        )
        
        # SECURE: Specific actions on specific resources
        secure_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LimitedS3Access",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": f"arn:aws:s3:::{config.S3_SECURE_BUCKET}/*"
                }
            ]
        }
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='secure-least-privilege-policy',
            PolicyDocument=json.dumps(secure_policy)
        )
        
        console.print(f"  [green]✓[/] Created with least-privilege permissions")
        return True
        
    except iam_client.exceptions.EntityAlreadyExistsException:
        console.print(f"  [yellow]! Role already exists[/]")
        return True
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def display_summary(account_id):
    """Display summary of created IAM resources"""
    table = Table(title="IAM Resources Created")
    table.add_column("Resource", style="cyan")
    table.add_column("Type", style="blue")
    table.add_column("Vulnerability", style="yellow")
    table.add_column("Severity", style="red")
    
    table.add_row(config.IAM_OVERPRIVILEGED_USER, "User", "Excessive Permissions", "🔴 Critical")
    table.add_row(config.IAM_ESCALATION_USER, "User", "Self-Escalation", "🔴 Critical")
    table.add_row(config.IAM_WEAK_TRUST_ROLE, "Role", "Weak Trust Policy", "🔴 Critical")
    table.add_row(config.IAM_WILDCARD_ROLE, "Role", "Wildcard Actions", "🔴 Critical")
    table.add_row(config.IAM_SECURE_ROLE, "Role", "None (Secure)", "🟢 N/A")
    
    console.print("\n")
    console.print(table)


def main():
    console.print(Panel.fit(
        "[bold red]⚠️  VULNERABLE IAM SETUP  ⚠️[/]\n"
        "This script creates intentionally insecure IAM resources.\n"
        "[yellow]For educational purposes only![/]",
        title="AWS Security Lab"
    ))
    
    iam_client = create_iam_client()
    account_id = get_account_id()
    
    console.print(f"\n[dim]AWS Account ID: {account_id}[/]")
    
    # Create all IAM resources
    create_overprivileged_user(iam_client, account_id)
    create_escalation_user(iam_client, account_id)
    create_weak_trust_role(iam_client, account_id)
    create_wildcard_role(iam_client, account_id)
    create_secure_role(iam_client, account_id)
    
    display_summary(account_id)
    
    console.print("\n[bold green]Setup complete![/]")
    console.print("Run penetration tests from: [cyan]penetration-testing/iam-escalation/[/]")


if __name__ == "__main__":
    main()
