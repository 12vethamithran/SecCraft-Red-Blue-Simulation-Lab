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
