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
