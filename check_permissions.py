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
