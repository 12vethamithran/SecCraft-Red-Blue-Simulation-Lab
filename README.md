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
