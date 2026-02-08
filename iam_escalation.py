"""
IAM Privilege Escalation Tool
==============================
Identifies and exploits IAM privilege escalation paths.

ATTACK TECHNIQUES:
1. Permission enumeration - Map current permissions
2. Escalation path detection - Find ways to elevate privileges
3. Policy abuse - Exploit misconfigured policies
4. Role assumption - Hijack overly permissive roles
"""

import boto3
import json
import sys
import os
from botocore.exceptions import ClientError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

console = Console()


# Known privilege escalation methods in AWS
ESCALATION_METHODS = {
    'iam:CreatePolicyVersion': {
        'description': 'Create a new version of a managed policy with elevated permissions',
        'severity': 'Critical',
        'technique': 'Create new policy version with admin permissions'
    },
    'iam:SetDefaultPolicyVersion': {
        'description': 'Set existing policy version as default (if older version has more perms)',
        'severity': 'High',
        'technique': 'Rollback to a more permissive policy version'
    },
    'iam:CreateAccessKey': {
        'description': 'Create access key for another user',
        'severity': 'Critical',
        'technique': 'Create access keys for admin users'
    },
    'iam:CreateLoginProfile': {
        'description': 'Create console password for another user',
        'severity': 'Critical',
        'technique': 'Create login for admin users'
    },
    'iam:UpdateLoginProfile': {
        'description': 'Change console password for another user',
        'severity': 'Critical',
        'technique': 'Reset admin user passwords'
    },
    'iam:AttachUserPolicy': {
        'description': 'Attach managed policy to user',
        'severity': 'Critical',
        'technique': 'Attach AdministratorAccess to yourself'
    },
    'iam:AttachGroupPolicy': {
        'description': 'Attach managed policy to group',
        'severity': 'Critical',
        'technique': 'Attach admin policy to your group'
    },
    'iam:AttachRolePolicy': {
        'description': 'Attach managed policy to role',
        'severity': 'Critical',
        'technique': 'Attach admin policy to assumable role'
    },
    'iam:PutUserPolicy': {
        'description': 'Add inline policy to user',
        'severity': 'Critical',
        'technique': 'Add inline admin policy to yourself'
    },
    'iam:PutGroupPolicy': {
        'description': 'Add inline policy to group',
        'severity': 'Critical',
        'technique': 'Add inline admin policy to your group'
    },
    'iam:PutRolePolicy': {
        'description': 'Add inline policy to role',
        'severity': 'Critical',
        'technique': 'Add inline admin policy to assumable role'
    },
    'iam:AddUserToGroup': {
        'description': 'Add user to group',
        'severity': 'High',
        'technique': 'Add yourself to admin group'
    },
    'iam:UpdateAssumeRolePolicy': {
        'description': 'Modify role trust policy',
        'severity': 'Critical',
        'technique': 'Allow yourself to assume admin role'
    },
    'iam:PassRole': {
        'description': 'Pass role to service',
        'severity': 'High',
        'technique': 'Pass admin role to Lambda/EC2'
    },
    'sts:AssumeRole': {
        'description': 'Assume another role',
        'severity': 'Variable',
        'technique': 'Assume a role with more permissions'
    },
    'lambda:CreateFunction': {
        'description': 'Create Lambda with attached role',
        'severity': 'High',
        'technique': 'Create Lambda with admin role, execute it'
    },
    'lambda:UpdateFunctionCode': {
        'description': 'Update Lambda function code',
        'severity': 'High',
        'technique': 'Hijack Lambda with privileged role'
    },
    'ec2:RunInstances': {
        'description': 'Launch EC2 with instance profile',
        'severity': 'High',
        'technique': 'Launch EC2 with admin role, access metadata'
    },
    'glue:CreateDevEndpoint': {
        'description': 'Create Glue endpoint with role',
        'severity': 'High',
        'technique': 'Create Glue endpoint with admin role, SSH in'
    },
    'cloudformation:CreateStack': {
        'description': 'Create CloudFormation stack with role',
        'severity': 'High',
        'technique': 'Create stack that creates admin resources'
    }
}


class IAMEnumerator:
    """IAM privilege escalation enumeration tool"""
    
    def __init__(self):
        self.iam_client = boto3.client('iam', region_name=config.AWS_REGION)
        self.sts_client = boto3.client('sts')
        self.current_identity = None
        self.permissions = []
        self.escalation_paths = []
    
    def get_current_identity(self):
        """Get current IAM identity"""
        try:
            identity = self.sts_client.get_caller_identity()
            self.current_identity = {
                'arn': identity['Arn'],
                'account': identity['Account'],
                'user_id': identity['UserId']
            }
            
            # Determine if user or role
            arn = identity['Arn']
            if ':user/' in arn:
                self.current_identity['type'] = 'user'
                self.current_identity['name'] = arn.split(':user/')[-1]
            elif ':role/' in arn:
                self.current_identity['type'] = 'role'
                self.current_identity['name'] = arn.split(':role/')[-1].split('/')[-1]
            elif ':assumed-role/' in arn:
                self.current_identity['type'] = 'assumed-role'
                self.current_identity['name'] = arn.split(':assumed-role/')[-1]
            else:
                self.current_identity['type'] = 'unknown'
                self.current_identity['name'] = arn.split('/')[-1]
            
            return self.current_identity
        except Exception as e:
            console.print(f"[red]Error getting identity:[/] {e}")
            return None
    
    def enumerate_user_policies(self, user_name):
        """Get all policies attached to a user"""
        policies = []
        
        try:
            # Inline policies
            inline = self.iam_client.list_user_policies(UserName=user_name)
            for policy_name in inline.get('PolicyNames', []):
                policy_doc = self.iam_client.get_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )
                policies.append({
                    'type': 'inline',
                    'name': policy_name,
                    'document': policy_doc['PolicyDocument']
                })
            
            # Attached managed policies
            attached = self.iam_client.list_attached_user_policies(UserName=user_name)
            for policy in attached.get('AttachedPolicies', []):
                policy_version = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                version_id = policy_version['Policy']['DefaultVersionId']
                policy_doc = self.iam_client.get_policy_version(
                    PolicyArn=policy['PolicyArn'],
                    VersionId=version_id
                )
                policies.append({
                    'type': 'managed',
                    'name': policy['PolicyName'],
                    'arn': policy['PolicyArn'],
                    'document': policy_doc['PolicyVersion']['Document']
                })
                
        except ClientError as e:
            console.print(f"[red]Error enumerating policies:[/] {e}")
        
        return policies
    
    def enumerate_role_policies(self, role_name):
        """Get all policies attached to a role"""
        policies = []
        
        try:
            # Inline policies
            inline = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get('PolicyNames', []):
                policy_doc = self.iam_client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policies.append({
                    'type': 'inline',
                    'name': policy_name,
                    'document': policy_doc['PolicyDocument']
                })
            
            # Attached managed policies
            attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get('AttachedPolicies', []):
                try:
                    policy_version = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                    version_id = policy_version['Policy']['DefaultVersionId']
                    policy_doc = self.iam_client.get_policy_version(
                        PolicyArn=policy['PolicyArn'],
                        VersionId=version_id
                    )
                    policies.append({
                        'type': 'managed',
                        'name': policy['PolicyName'],
                        'arn': policy['PolicyArn'],
                        'document': policy_doc['PolicyVersion']['Document']
                    })
                except:
                    policies.append({
                        'type': 'managed',
                        'name': policy['PolicyName'],
                        'arn': policy['PolicyArn'],
                        'document': None
                    })
                    
        except ClientError as e:
            console.print(f"[red]Error enumerating role policies:[/] {e}")
        
        return policies
    
    def extract_permissions(self, policies):
        """Extract all allowed actions from policies"""
        permissions = set()
        
        for policy in policies:
            doc = policy.get('document')
            if not doc:
                continue
            
            for statement in doc.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    
                    for action in actions:
                        permissions.add(action)
        
        return list(permissions)
    
    def find_escalation_paths(self, permissions):
        """Identify privilege escalation paths from current permissions"""
        paths = []
        
        for perm in permissions:
            # Handle wildcards
            if perm == '*' or perm == '*:*':
                paths.append({
                    'permission': perm,
                    'method': 'Full Admin Access',
                    'severity': 'Critical',
                    'description': 'Has all permissions - no escalation needed!',
                    'technique': 'Already has full access'
                })
                continue
            
            # Check for service wildcards
            if perm.endswith(':*'):
                service = perm.split(':')[0]
                if service == 'iam':
                    paths.append({
                        'permission': perm,
                        'method': 'IAM Wildcard',
                        'severity': 'Critical',
                        'description': 'Full IAM access allows any escalation method',
                        'technique': 'Use any IAM escalation technique'
                    })
            
            # Check against known escalation methods
            for method, details in ESCALATION_METHODS.items():
                if perm == method or perm.replace(':*', '') == method.split(':')[0]:
                    paths.append({
                        'permission': perm,
                        'method': method,
                        'severity': details['severity'],
                        'description': details['description'],
                        'technique': details['technique']
                    })
        
        return paths
    
    def check_assumable_roles(self):
        """Find roles that can be assumed"""
        assumable = []
        
        try:
            roles = self.iam_client.list_roles(MaxItems=100)
            
            for role in roles.get('Roles', []):
                trust_policy = role.get('AssumeRolePolicyDocument', {})
                
                for statement in trust_policy.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        
                        # Check if anyone can assume
                        if principal == '*' or principal.get('AWS') == '*':
                            assumable.append({
                                'role_name': role['RoleName'],
                                'role_arn': role['Arn'],
                                'vulnerability': 'Any principal can assume this role!',
                                'severity': 'Critical'
                            })
                        
                        # Check if current account can assume
                        elif isinstance(principal.get('AWS'), str):
                            if self.current_identity['account'] in principal['AWS']:
                                assumable.append({
                                    'role_name': role['RoleName'],
                                    'role_arn': role['Arn'],
                                    'vulnerability': 'Account can assume this role',
                                    'severity': 'High'
                                })
                                
        except ClientError as e:
            console.print(f"[yellow]Cannot list roles:[/] {e}")
        
        return assumable
    
    def attempt_assume_role(self, role_arn):
        """Attempt to assume a role"""
        try:
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='SecurityLabTest'
            )
            return {
                'success': True,
                'credentials': {
                    'AccessKeyId': response['Credentials']['AccessKeyId'],
                    'SecretAccessKey': response['Credentials']['SecretAccessKey'][:10] + '...',
                    'SessionToken': response['Credentials']['SessionToken'][:20] + '...',
                    'Expiration': str(response['Credentials']['Expiration'])
                }
            }
        except ClientError as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def check_dangerous_policies(self):
        """Scan for dangerously permissive policies"""
        dangerous = []
        
        try:
            # List customer managed policies
            policies = self.iam_client.list_policies(Scope='Local', MaxItems=100)
            
            for policy in policies.get('Policies', []):
                try:
                    version = self.iam_client.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )
                    doc = version['PolicyVersion']['Document']
                    
                    for statement in doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])
                            
                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]
                            
                            # Check for admin access
                            if '*' in actions and '*' in resources:
                                dangerous.append({
                                    'policy_name': policy['PolicyName'],
                                    'policy_arn': policy['Arn'],
                                    'issue': 'Allow * on * (Admin access)',
                                    'severity': 'Critical'
                                })
                            elif any(a.startswith('iam:') or a == '*' for a in actions):
                                dangerous.append({
                                    'policy_name': policy['PolicyName'],
                                    'policy_arn': policy['Arn'],
                                    'issue': f'IAM actions allowed: {[a for a in actions if a.startswith("iam:") or a == "*"]}',
                                    'severity': 'High'
                                })
                except:
                    pass
                    
        except ClientError as e:
            console.print(f"[yellow]Cannot scan policies:[/] {e}")
        
        return dangerous


def main():
    console.print(Panel.fit(
        "[bold red]🔓 IAM PRIVILEGE ESCALATION TOOL 🔓[/]\n\n"
        "This tool identifies privilege escalation paths:\n"
        "• Maps current IAM permissions\n"
        "• Identifies escalation techniques\n"
        "• Finds assumable roles\n"
        "• Detects dangerous policies",
        title="Penetration Testing Tool"
    ))
    
    enumerator = IAMEnumerator()
    
    # Get current identity
    console.print("\n[bold cyan]1. Current Identity[/]")
    console.print("-" * 40)
    identity = enumerator.get_current_identity()
    
    if identity:
        console.print(f"  ARN: [green]{identity['arn']}[/]")
        console.print(f"  Type: {identity['type']}")
        console.print(f"  Name: {identity['name']}")
        console.print(f"  Account: {identity['account']}")
    
    # Enumerate permissions
    console.print("\n[bold cyan]2. Enumerating Permissions[/]")
    console.print("-" * 40)
    
    policies = []
    if identity['type'] == 'user':
        policies = enumerator.enumerate_user_policies(identity['name'])
    elif identity['type'] in ['role', 'assumed-role']:
        role_name = identity['name'].split('/')[0] if '/' in identity['name'] else identity['name']
        policies = enumerator.enumerate_role_policies(role_name)
    
    console.print(f"  Found {len(policies)} policies")
    
    permissions = enumerator.extract_permissions(policies)
    console.print(f"  Total unique permissions: {len(permissions)}")
    
    # Show permission tree
    if permissions:
        tree = Tree("[bold]Permissions[/]")
        services = {}
        for perm in sorted(permissions):
            service = perm.split(':')[0] if ':' in perm else 'other'
            if service not in services:
                services[service] = []
            services[service].append(perm)
        
        for service, perms in sorted(services.items())[:10]:  # Show first 10 services
            branch = tree.add(f"[cyan]{service}[/]")
            for p in perms[:5]:  # Show first 5 permissions per service
                branch.add(p)
            if len(perms) > 5:
                branch.add(f"[dim]... and {len(perms)-5} more[/]")
        
        console.print(tree)
    
    # Find escalation paths
    console.print("\n[bold cyan]3. Privilege Escalation Paths[/]")
    console.print("-" * 40)
    
    escalation_paths = enumerator.find_escalation_paths(permissions)
    
    if escalation_paths:
        table = Table(title="Escalation Opportunities")
        table.add_column("Permission", style="cyan")
        table.add_column("Method", style="yellow")
        table.add_column("Severity", style="red")
        table.add_column("Technique", style="green")
        
        for path in escalation_paths:
            table.add_row(
                path['permission'][:30],
                path['method'],
                path['severity'],
                path['technique'][:40]
            )
        
        console.print(table)
    else:
        console.print("  [green]No obvious escalation paths found[/]")
    
    # Check assumable roles
    console.print("\n[bold cyan]4. Assumable Roles[/]")
    console.print("-" * 40)
    
    assumable_roles = enumerator.check_assumable_roles()
    
    if assumable_roles:
        for role in assumable_roles:
            console.print(f"  [red]⚠ {role['role_name']}[/]")
            console.print(f"    Vulnerability: {role['vulnerability']}")
            console.print(f"    ARN: {role['role_arn']}")
    else:
        console.print("  [green]No easily assumable roles found[/]")
    
    # Check dangerous policies
    console.print("\n[bold cyan]5. Dangerous Policies[/]")
    console.print("-" * 40)
    
    dangerous = enumerator.check_dangerous_policies()
    
    if dangerous:
        for policy in dangerous:
            console.print(f"  [red]⚠ {policy['policy_name']}[/]")
            console.print(f"    Issue: {policy['issue']}")
    else:
        console.print("  [green]No obviously dangerous policies found[/]")
    
    console.print("\n[bold green]Enumeration complete![/]")


if __name__ == "__main__":
    main()
