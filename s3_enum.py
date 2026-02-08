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
