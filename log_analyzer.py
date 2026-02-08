"""
CloudTrail Log Analyzer
========================
SOC tool for analyzing AWS CloudTrail logs and detecting suspicious activity.

DETECTION CAPABILITIES:
1. Unauthorized API calls
2. Console logins from unusual locations
3. Security group modifications
4. IAM policy changes
5. S3 bucket policy changes
6. Root account usage
"""

import boto3
import json
import gzip
import sys
import os
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

console = Console()


# Suspicious event patterns
SUSPICIOUS_EVENTS = {
    # IAM Events
    'CreateUser': {'severity': 'Medium', 'category': 'IAM', 'description': 'New user created'},
    'CreateAccessKey': {'severity': 'High', 'category': 'IAM', 'description': 'Access key created'},
    'AttachUserPolicy': {'severity': 'High', 'category': 'IAM', 'description': 'Policy attached to user'},
    'AttachRolePolicy': {'severity': 'High', 'category': 'IAM', 'description': 'Policy attached to role'},
    'PutUserPolicy': {'severity': 'High', 'category': 'IAM', 'description': 'Inline policy added to user'},
    'DeleteAccessKey': {'severity': 'Medium', 'category': 'IAM', 'description': 'Access key deleted'},
    'UpdateAssumeRolePolicy': {'severity': 'Critical', 'category': 'IAM', 'description': 'Role trust policy modified'},
    
    # S3 Events
    'PutBucketPolicy': {'severity': 'High', 'category': 'S3', 'description': 'Bucket policy modified'},
    'DeleteBucketPolicy': {'severity': 'Medium', 'category': 'S3', 'description': 'Bucket policy deleted'},
    'PutBucketAcl': {'severity': 'High', 'category': 'S3', 'description': 'Bucket ACL modified'},
    'PutBucketPublicAccessBlock': {'severity': 'High', 'category': 'S3', 'description': 'Public access settings changed'},
    
    # EC2 Events
    'AuthorizeSecurityGroupIngress': {'severity': 'High', 'category': 'EC2', 'description': 'Security group rule added'},
    'AuthorizeSecurityGroupEgress': {'severity': 'Medium', 'category': 'EC2', 'description': 'Egress rule added'},
    'RunInstances': {'severity': 'Medium', 'category': 'EC2', 'description': 'EC2 instance launched'},
    'StopInstances': {'severity': 'Low', 'category': 'EC2', 'description': 'EC2 instance stopped'},
    'TerminateInstances': {'severity': 'Medium', 'category': 'EC2', 'description': 'EC2 instance terminated'},
    
    # CloudTrail Events
    'StopLogging': {'severity': 'Critical', 'category': 'CloudTrail', 'description': 'CloudTrail logging stopped!'},
    'DeleteTrail': {'severity': 'Critical', 'category': 'CloudTrail', 'description': 'CloudTrail deleted!'},
    'UpdateTrail': {'severity': 'High', 'category': 'CloudTrail', 'description': 'CloudTrail configuration changed'},
    
    # Console Access
    'ConsoleLogin': {'severity': 'Info', 'category': 'Access', 'description': 'Console login'},
    
    # GuardDuty
    'DisableGuardDuty': {'severity': 'Critical', 'category': 'Security', 'description': 'GuardDuty disabled!'},
    'DeleteDetector': {'severity': 'Critical', 'category': 'Security', 'description': 'GuardDuty detector deleted!'},
}

# Known attack patterns
ATTACK_PATTERNS = {
    'credential_theft': [
        'GetSecretValue', 'GetParametersByPath', 'GetParameters',
        'ListSecrets', 'DescribeSecret'
    ],
    'reconnaissance': [
        'ListUsers', 'ListRoles', 'ListPolicies', 'ListBuckets',
        'DescribeInstances', 'GetAccountAuthorizationDetails'
    ],
    'privilege_escalation': [
        'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy',
        'PutRolePolicy', 'CreatePolicyVersion', 'SetDefaultPolicyVersion'
    ],
    'persistence': [
        'CreateUser', 'CreateAccessKey', 'CreateLoginProfile',
        'CreateRole', 'UpdateAssumeRolePolicy'
    ],
    'defense_evasion': [
        'StopLogging', 'DeleteTrail', 'DeleteFlowLogs',
        'DisableGuardDuty', 'DeleteDetector'
    ]
}


class CloudTrailAnalyzer:
    """Analyzes CloudTrail logs for security threats"""
    
    def __init__(self):
        self.cloudtrail = boto3.client('cloudtrail', region_name=config.AWS_REGION)
        self.s3 = boto3.client('s3', region_name=config.AWS_REGION)
        self.findings = []
        self.event_stats = defaultdict(int)
        self.user_activity = defaultdict(list)
    
    def lookup_recent_events(self, hours=24, max_results=1000):
        """Query CloudTrail for recent events"""
        console.print(f"\n[bold cyan]Querying CloudTrail events (last {hours} hours)...[/]")
        
        start_time = datetime.utcnow() - timedelta(hours=hours)
        events = []
        
        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=datetime.utcnow(),
                MaxResults=min(max_results, 50)
            ):
                for event in page.get('Events', []):
                    events.append(event)
                    if len(events) >= max_results:
                        break
                if len(events) >= max_results:
                    break
            
            console.print(f"  [green]Retrieved {len(events)} events[/]")
            return events
            
        except Exception as e:
            console.print(f"  [red]Error querying CloudTrail:[/] {e}")
            return []
    
    def parse_event(self, event):
        """Parse CloudTrail event into structured format"""
        try:
            cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
            return {
                'event_id': event.get('EventId'),
                'event_name': event.get('EventName'),
                'event_time': event.get('EventTime'),
                'username': event.get('Username', 'Unknown'),
                'event_source': cloud_trail_event.get('eventSource', ''),
                'source_ip': cloud_trail_event.get('sourceIPAddress', ''),
                'user_agent': cloud_trail_event.get('userAgent', ''),
                'error_code': cloud_trail_event.get('errorCode'),
                'error_message': cloud_trail_event.get('errorMessage'),
                'request_params': cloud_trail_event.get('requestParameters', {}),
                'response_elements': cloud_trail_event.get('responseElements', {}),
                'user_identity': cloud_trail_event.get('userIdentity', {}),
                'raw': cloud_trail_event
            }
        except:
            return None
    
    def analyze_event(self, parsed_event):
        """Analyze a single event for suspicious activity"""
        event_name = parsed_event['event_name']
        findings = []
        
        # Check against known suspicious events
        if event_name in SUSPICIOUS_EVENTS:
            info = SUSPICIOUS_EVENTS[event_name]
            findings.append({
                'type': 'suspicious_event',
                'event_name': event_name,
                'severity': info['severity'],
                'category': info['category'],
                'description': info['description'],
                'username': parsed_event['username'],
                'source_ip': parsed_event['source_ip'],
                'time': parsed_event['event_time']
            })
        
        # Check for failed API calls (potential reconnaissance)
        if parsed_event['error_code']:
            if parsed_event['error_code'] in ['AccessDenied', 'UnauthorizedAccess']:
                findings.append({
                    'type': 'access_denied',
                    'event_name': event_name,
                    'severity': 'Medium',
                    'category': 'Reconnaissance',
                    'description': f"Access denied: {parsed_event['error_message']}",
                    'username': parsed_event['username'],
                    'source_ip': parsed_event['source_ip'],
                    'time': parsed_event['event_time']
                })
        
        # Check for root account usage
        user_identity = parsed_event['user_identity']
        if user_identity.get('type') == 'Root':
            findings.append({
                'type': 'root_activity',
                'event_name': event_name,
                'severity': 'Critical',
                'category': 'Access',
                'description': 'Root account activity detected!',
                'username': 'Root',
                'source_ip': parsed_event['source_ip'],
                'time': parsed_event['event_time']
            })
        
        # Check for console login without MFA
        if event_name == 'ConsoleLogin':
            additional_data = parsed_event['raw'].get('additionalEventData', {})
            if not additional_data.get('MFAUsed') == 'Yes':
                findings.append({
                    'type': 'no_mfa',
                    'event_name': event_name,
                    'severity': 'High',
                    'category': 'Access',
                    'description': 'Console login without MFA!',
                    'username': parsed_event['username'],
                    'source_ip': parsed_event['source_ip'],
                    'time': parsed_event['event_time']
                })
        
        return findings
    
    def detect_attack_patterns(self, events):
        """Detect attack patterns from event sequences"""
        console.print("\n[bold cyan]Detecting Attack Patterns...[/]")
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            parsed = self.parse_event(event)
            if parsed:
                user_events[parsed['username']].append(parsed['event_name'])
        
        pattern_findings = []
        
        for username, event_names in user_events.items():
            event_set = set(event_names)
            
            for pattern_name, pattern_events in ATTACK_PATTERNS.items():
                matches = event_set.intersection(set(pattern_events))
                if len(matches) >= 2:  # At least 2 matching events
                    pattern_findings.append({
                        'pattern': pattern_name,
                        'username': username,
                        'matching_events': list(matches),
                        'severity': 'High' if pattern_name in ['privilege_escalation', 'defense_evasion'] else 'Medium'
                    })
        
        return pattern_findings
    
    def analyze_ip_addresses(self, events):
        """Analyze source IP addresses for anomalies"""
        console.print("\n[bold cyan]Analyzing Source IPs...[/]")
        
        ip_activity = defaultdict(lambda: {'count': 0, 'users': set(), 'events': set()})
        
        for event in events:
            parsed = self.parse_event(event)
            if parsed and parsed['source_ip']:
                ip = parsed['source_ip']
                ip_activity[ip]['count'] += 1
                ip_activity[ip]['users'].add(parsed['username'])
                ip_activity[ip]['events'].add(parsed['event_name'])
        
        suspicious_ips = []
        for ip, data in ip_activity.items():
            # Flag IPs with multiple users (potential credential stuffing)
            if len(data['users']) > 3:
                suspicious_ips.append({
                    'ip': ip,
                    'reason': f"Multiple users ({len(data['users'])}) from same IP",
                    'users': list(data['users']),
                    'severity': 'High'
                })
            
            # Flag IPs with high event count
            if data['count'] > 100:
                suspicious_ips.append({
                    'ip': ip,
                    'reason': f"High activity volume ({data['count']} events)",
                    'severity': 'Medium'
                })
        
        return suspicious_ips
    
    def generate_report(self, events):
        """Generate comprehensive security report"""
        all_findings = []
        
        # Analyze each event
        console.print("\n[bold cyan]Analyzing Events...[/]")
        with Progress() as progress:
            task = progress.add_task("Processing...", total=len(events))
            
            for event in events:
                parsed = self.parse_event(event)
                if parsed:
                    findings = self.analyze_event(parsed)
                    all_findings.extend(findings)
                    self.event_stats[parsed['event_name']] += 1
                    self.user_activity[parsed['username']].append(parsed)
                progress.advance(task)
        
        # Detect attack patterns
        patterns = self.detect_attack_patterns(events)
        
        # Analyze IPs
        suspicious_ips = self.analyze_ip_addresses(events)
        
        return {
            'total_events': len(events),
            'findings': all_findings,
            'patterns': patterns,
            'suspicious_ips': suspicious_ips,
            'event_stats': dict(self.event_stats),
            'active_users': len(self.user_activity)
        }
    
    def display_report(self, report):
        """Display the security report"""
        console.print("\n" + "="*60)
        console.print("[bold]SECURITY ANALYSIS REPORT[/]")
        console.print("="*60)
        
        # Summary
        console.print(f"\n[cyan]Total Events Analyzed:[/] {report['total_events']}")
        console.print(f"[cyan]Active Users:[/] {report['active_users']}")
        console.print(f"[cyan]Findings:[/] {len(report['findings'])}")
        console.print(f"[cyan]Attack Patterns:[/] {len(report['patterns'])}")
        console.print(f"[cyan]Suspicious IPs:[/] {len(report['suspicious_ips'])}")
        
        # Findings by severity
        if report['findings']:
            console.print("\n[bold red]SECURITY FINDINGS[/]")
            
            table = Table()
            table.add_column("Time", style="dim")
            table.add_column("Severity", style="bold")
            table.add_column("Category")
            table.add_column("Event")
            table.add_column("User")
            table.add_column("Source IP")
            
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
            sorted_findings = sorted(report['findings'], 
                                    key=lambda x: severity_order.get(x['severity'], 5))
            
            for finding in sorted_findings[:20]:  # Show top 20
                severity_color = {
                    'Critical': 'red',
                    'High': 'yellow',
                    'Medium': 'blue',
                    'Low': 'green'
                }.get(finding['severity'], 'white')
                
                table.add_row(
                    str(finding.get('time', ''))[:19],
                    f"[{severity_color}]{finding['severity']}[/]",
                    finding['category'],
                    finding['event_name'],
                    finding['username'][:15],
                    finding['source_ip']
                )
            
            console.print(table)
        
        # Attack patterns
        if report['patterns']:
            console.print("\n[bold red]ATTACK PATTERNS DETECTED[/]")
            for pattern in report['patterns']:
                console.print(f"  [yellow]⚠ {pattern['pattern'].upper()}[/]")
                console.print(f"    User: {pattern['username']}")
                console.print(f"    Events: {', '.join(pattern['matching_events'])}")
        
        # Suspicious IPs
        if report['suspicious_ips']:
            console.print("\n[bold red]SUSPICIOUS IP ADDRESSES[/]")
            for ip_info in report['suspicious_ips']:
                console.print(f"  [yellow]⚠ {ip_info['ip']}[/]")
                console.print(f"    Reason: {ip_info['reason']}")
        
        # Top events
        console.print("\n[bold cyan]TOP EVENTS[/]")
        sorted_events = sorted(report['event_stats'].items(), key=lambda x: x[1], reverse=True)
        for event, count in sorted_events[:10]:
            console.print(f"  {event}: {count}")


def main():
    console.print(Panel.fit(
        "[bold cyan]🔍 CLOUDTRAIL LOG ANALYZER 🔍[/]\n\n"
        "SOC tool for detecting security threats:\n"
        "• Suspicious API calls\n"
        "• Attack pattern detection\n"
        "• Anomalous IP analysis\n"
        "• Root account usage alerts",
        title="Security Operations Center"
    ))
    
    analyzer = CloudTrailAnalyzer()
    
    # Query recent events
    events = analyzer.lookup_recent_events(hours=24, max_results=500)
    
    if events:
        # Generate and display report
        report = analyzer.generate_report(events)
        analyzer.display_report(report)
        
        # Save report
        report_file = 'security_report.json'
        with open(report_file, 'w') as f:
            # Convert non-serializable objects
            export_report = {
                'generated_at': datetime.utcnow().isoformat(),
                'total_events': report['total_events'],
                'findings_count': len(report['findings']),
                'patterns': report['patterns'],
                'suspicious_ips': report['suspicious_ips'],
                'event_stats': report['event_stats']
            }
            json.dump(export_report, f, indent=2, default=str)
        console.print(f"\n[green]Report saved to {report_file}[/]")
    else:
        console.print("\n[yellow]No events found. Make sure CloudTrail is enabled.[/]")
    
    console.print("\n[bold green]Analysis complete![/]")


if __name__ == "__main__":
    main()
