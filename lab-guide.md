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
