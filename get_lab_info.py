import boto3
import sys
import os

# Add parent directory to path to import config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import config
except ImportError:
    # Fallback if run from utils dir directly without python path set
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from config import config

# Create EC2 client
try:
    ec2 = boto3.client('ec2', region_name=config.AWS_REGION)
    
    # Filter for the vulnerable instance
    response = ec2.describe_instances(
        Filters=[
            {'Name': 'tag:Vulnerability', 'Values': ['imdsv1-enabled']},
            {'Name': 'instance-state-name', 'Values': ['running']}
        ]
    )
    
    found = False
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            public_ip = instance.get('PublicIpAddress')
            if public_ip:
                url = f"http://{public_ip}/proxy?url=http://169.254.169.254/latest/meta-data/instance-id"
                print(f"URL: {url}")
                with open("ip_info.txt", "w") as f:
                    f.write(url)
                found = True
            else:
                print("Error: No Public IP")
    
    if not found:
        print("Error: Instance not found")

except Exception as e:
    print(f"Error accessing AWS: {e}")
