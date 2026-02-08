"""
Vulnerable S3 Bucket Setup
==========================
Creates intentionally vulnerable S3 buckets for security testing.

VULNERABILITIES CREATED:
1. Public bucket with open access
2. Bucket without encryption
3. Bucket without versioning
4. Bucket with overly permissive CORS

WARNING: These are intentionally insecure configurations for educational purposes only!
"""

import boto3
import json
import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def create_s3_client():
    """Create boto3 S3 client"""
    return boto3.client('s3', region_name=config.AWS_REGION)


def create_public_bucket(s3_client):
    """
    VULNERABILITY 1: Public S3 Bucket
    ---------------------------------
    Attack Vector: Direct URL access, bucket enumeration
    Risk: Data exposure, sensitive information leakage
    """
    bucket_name = config.S3_PUBLIC_BUCKET
    console.print(f"\n[bold red]Creating PUBLIC bucket:[/] {bucket_name}")
    
    try:
        # Create bucket
        if config.AWS_REGION == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': config.AWS_REGION}
            )
        
        # VULNERABLE: Disable all public access blocks
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': False,       # VULNERABLE
                'IgnorePublicAcls': False,      # VULNERABLE
                'BlockPublicPolicy': False,     # VULNERABLE
                'RestrictPublicBuckets': False  # VULNERABLE
            }
        )
        
        # VULNERABLE: Public read policy
        public_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",  # VULNERABLE: Anyone can access
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ]
                }
            ]
        }
        s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))
        
        # Add sample "sensitive" files
        s3_client.put_object(
            Bucket=bucket_name,
            Key='backup/credentials.txt',
            Body=config.SAMPLE_CREDENTIALS,
            ContentType='text/plain'
        )
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key='config/app-config.json',
            Body=json.dumps(config.SAMPLE_CONFIG, indent=2),
            ContentType='application/json'
        )
        
        # Add tagging
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [
                {'Key': 'Vulnerability', 'Value': 'public-access'},
                {'Key': 'Severity', 'Value': 'Critical'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]}
        )
        
        console.print(f"  [green]✓[/] Created with PUBLIC access")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Anyone can read bucket contents")
        return True
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_unencrypted_bucket(s3_client):
    """
    VULNERABILITY 2: No Encryption
    ------------------------------
    Attack Vector: Data interception, compliance violation
    Risk: Data at rest not protected
    """
    bucket_name = config.S3_UNENCRYPTED_BUCKET
    console.print(f"\n[bold red]Creating UNENCRYPTED bucket:[/] {bucket_name}")
    
    try:
        if config.AWS_REGION == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': config.AWS_REGION}
            )
        
        # NOTE: Not setting encryption = vulnerable
        # Best practice would be:
        # s3_client.put_bucket_encryption(...)
        
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [
                {'Key': 'Vulnerability', 'Value': 'no-encryption'},
                {'Key': 'Severity', 'Value': 'High'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]}
        )
        
        console.print(f"  [green]✓[/] Created without server-side encryption")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Data at rest is not encrypted")
        return True
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_no_versioning_bucket(s3_client):
    """
    VULNERABILITY 3: No Versioning
    ------------------------------
    Attack Vector: Data destruction, ransomware
    Risk: No recovery from accidental/malicious deletion
    """
    bucket_name = config.S3_NO_VERSIONING_BUCKET
    console.print(f"\n[bold red]Creating NO-VERSIONING bucket:[/] {bucket_name}")
    
    try:
        if config.AWS_REGION == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': config.AWS_REGION}
            )
        
        # VULNERABLE: Versioning suspended/disabled
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Suspended'}  # VULNERABLE
        )
        
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [
                {'Key': 'Vulnerability', 'Value': 'no-versioning'},
                {'Key': 'Severity', 'Value': 'Medium'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]}
        )
        
        console.print(f"  [green]✓[/] Created with versioning DISABLED")
        console.print(f"  [yellow]⚠ Vulnerability:[/] No protection against data deletion")
        return True
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_cors_vulnerable_bucket(s3_client):
    """
    VULNERABILITY 4: Overly Permissive CORS
    ---------------------------------------
    Attack Vector: Cross-site data exfiltration
    Risk: Any website can access bucket data
    """
    bucket_name = config.S3_CORS_BUCKET
    console.print(f"\n[bold red]Creating CORS-VULNERABLE bucket:[/] {bucket_name}")
    
    try:
        if config.AWS_REGION == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': config.AWS_REGION}
            )
        
        # VULNERABLE: Allow any origin
        s3_client.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration={
                'CORSRules': [
                    {
                        'AllowedHeaders': ['*'],                    # VULNERABLE
                        'AllowedMethods': ['GET', 'PUT', 'POST', 'DELETE'],  # VULNERABLE
                        'AllowedOrigins': ['*'],                    # VULNERABLE
                        'ExposeHeaders': ['ETag'],
                        'MaxAgeSeconds': 3000
                    }
                ]
            }
        )
        
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [
                {'Key': 'Vulnerability', 'Value': 'overly-permissive-cors'},
                {'Key': 'Severity', 'Value': 'High'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]}
        )
        
        console.print(f"  [green]✓[/] Created with permissive CORS")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Any website can access bucket via browser")
        return True
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def create_secure_bucket(s3_client):
    """
    SECURE REFERENCE BUCKET
    -----------------------
    Demonstrates best practices for S3 security
    """
    bucket_name = config.S3_SECURE_BUCKET
    console.print(f"\n[bold green]Creating SECURE reference bucket:[/] {bucket_name}")
    
    try:
        if config.AWS_REGION == 'us-east-1':
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': config.AWS_REGION}
            )
        
        # SECURE: Block all public access
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # SECURE: Enable versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        # SECURE: Enable encryption
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        },
                        'BucketKeyEnabled': True
                    }
                ]
            }
        )
        
        s3_client.put_bucket_tagging(
            Bucket=bucket_name,
            Tagging={'TagSet': [
                {'Key': 'Vulnerability', 'Value': 'none'},
                {'Key': 'Purpose', 'Value': 'secure-reference'},
                *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
            ]}
        )
        
        console.print(f"  [green]✓[/] Created with all security best practices")
        return True
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return False


def display_summary():
    """Display summary of created buckets"""
    table = Table(title="S3 Buckets Created")
    table.add_column("Bucket Name", style="cyan")
    table.add_column("Vulnerability", style="yellow")
    table.add_column("Severity", style="red")
    
    table.add_row(config.S3_PUBLIC_BUCKET, "Public Access", "🔴 Critical")
    table.add_row(config.S3_UNENCRYPTED_BUCKET, "No Encryption", "🟠 High")
    table.add_row(config.S3_NO_VERSIONING_BUCKET, "No Versioning", "🟡 Medium")
    table.add_row(config.S3_CORS_BUCKET, "Permissive CORS", "🟠 High")
    table.add_row(config.S3_SECURE_BUCKET, "None (Secure)", "🟢 N/A")
    
    console.print("\n")
    console.print(table)


def main():
    console.print(Panel.fit(
        "[bold red]⚠️  VULNERABLE S3 BUCKET SETUP  ⚠️[/]\n"
        "This script creates intentionally insecure S3 buckets.\n"
        "[yellow]For educational purposes only![/]",
        title="AWS Security Lab"
    ))
    
    s3_client = create_s3_client()
    
    # Create all vulnerable buckets
    create_public_bucket(s3_client)
    create_unencrypted_bucket(s3_client)
    create_no_versioning_bucket(s3_client)
    create_cors_vulnerable_bucket(s3_client)
    create_secure_bucket(s3_client)
    
    display_summary()
    
    console.print("\n[bold green]Setup complete![/]")
    console.print("Run penetration tests from: [cyan]penetration-testing/s3-enumeration/[/]")


if __name__ == "__main__":
    main()
