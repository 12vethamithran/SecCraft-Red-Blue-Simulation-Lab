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
