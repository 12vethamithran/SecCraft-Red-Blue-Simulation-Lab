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
