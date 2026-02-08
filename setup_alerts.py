"""
CloudWatch Alerting Setup
=========================
Deploys CloudWatch metric filters and alarms based on alert definitions.
"""

import boto3
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from config import config

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


class AlertingSetup:
    """Sets up CloudWatch alerting infrastructure"""
    
    def __init__(self):
        self.logs = boto3.client('logs', region_name=config.AWS_REGION)
        self.cloudwatch = boto3.client('cloudwatch', region_name=config.AWS_REGION)
        self.sns = boto3.client('sns', region_name=config.AWS_REGION)
    
    def load_alert_definitions(self, file_path):
        """Load alert definitions from JSON file"""
        with open(file_path, 'r') as f:
            return json.load(f)
    
    def create_metric_filter(self, log_group, alarm_def):
        """Create CloudWatch metric filter"""
        try:
            self.logs.put_metric_filter(
                logGroupName=log_group,
                filterName=alarm_def['Name'],
                filterPattern=alarm_def['FilterPattern'],
                metricTransformations=[{
                    'metricName': alarm_def['MetricName'],
                    'metricNamespace': alarm_def['Namespace'],
                    'metricValue': '1',
                    'defaultValue': 0
                }]
            )
            return True
        except Exception as e:
            console.print(f"  [red]Error creating filter {alarm_def['Name']}:[/] {e}")
            return False
    
    def create_alarm(self, alarm_def, sns_topic_arn=None):
        """Create CloudWatch alarm"""
        try:
            alarm_params = {
                'AlarmName': f"SecurityLab-{alarm_def['Name']}",
                'AlarmDescription': alarm_def['Description'],
                'MetricName': alarm_def['MetricName'],
                'Namespace': alarm_def['Namespace'],
                'Statistic': alarm_def['Statistic'],
                'Period': alarm_def['Period'],
                'EvaluationPeriods': alarm_def['EvaluationPeriods'],
                'Threshold': alarm_def['Threshold'],
                'ComparisonOperator': alarm_def['ComparisonOperator'],
                'TreatMissingData': 'notBreaching',
                'Tags': [
                    {'Key': 'Severity', 'Value': alarm_def['Severity']},
                    {'Key': 'Project', 'Value': 'aws-security-lab'}
                ]
            }
            
            if sns_topic_arn:
                alarm_params['AlarmActions'] = [sns_topic_arn]
                alarm_params['OKActions'] = [sns_topic_arn]
            
            self.cloudwatch.put_metric_alarm(**alarm_params)
            return True
        except Exception as e:
            console.print(f"  [red]Error creating alarm {alarm_def['Name']}:[/] {e}")
            return False
    
    def get_or_create_sns_topic(self):
        """Get or create SNS topic for alerts"""
        topic_name = f"{config.LAB_PREFIX}-security-alerts"
        
        try:
            # Check if topic exists
            topics = self.sns.list_topics()
            for topic in topics.get('Topics', []):
                if topic_name in topic['TopicArn']:
                    return topic['TopicArn']
            
            # Create new topic
            response = self.sns.create_topic(Name=topic_name)
            return response['TopicArn']
        except Exception as e:
            console.print(f"[red]Error with SNS topic:[/] {e}")
            return None
    
    def deploy_all_alerts(self, alerts_file, log_group):
        """Deploy all alert definitions"""
        console.print(Panel.fit(
            "[bold cyan]🚨 DEPLOYING SECURITY ALERTS 🚨[/]\n\n"
            "Setting up CloudWatch metric filters and alarms\n"
            "for security monitoring.",
            title="Alerting Setup"
        ))
        
        # Load definitions
        definitions = self.load_alert_definitions(alerts_file)
        alarms = definitions.get('Alarms', [])
        
        console.print(f"\n[cyan]Found {len(alarms)} alert definitions[/]")
        
        # Get SNS topic
        sns_arn = self.get_or_create_sns_topic()
        if sns_arn:
            console.print(f"[green]SNS Topic:[/] {sns_arn}")
        
        # Deploy each alert
        results = {'filters': 0, 'alarms': 0, 'errors': 0}
        
        for alarm_def in alarms:
            console.print(f"\n[bold]{alarm_def['Name']}[/]")
            
            # Create metric filter
            if self.create_metric_filter(log_group, alarm_def):
                console.print(f"  [green]✓[/] Metric filter created")
                results['filters'] += 1
            else:
                results['errors'] += 1
            
            # Create alarm
            if self.create_alarm(alarm_def, sns_arn):
                console.print(f"  [green]✓[/] Alarm created")
                results['alarms'] += 1
            else:
                results['errors'] += 1
        
        # Summary
        console.print("\n" + "="*40)
        console.print("[bold]Deployment Summary[/]")
        console.print(f"  Metric Filters: {results['filters']}")
        console.print(f"  Alarms: {results['alarms']}")
        console.print(f"  Errors: {results['errors']}")


def main():
    setup = AlertingSetup()
    
    # Get path to alerts file
    alerts_file = os.path.join(os.path.dirname(__file__), 'cloudwatch_alerts.json')
    
    # Deploy alerts
    setup.deploy_all_alerts(alerts_file, config.CLOUDWATCH_LOG_GROUP)
    
    console.print("\n[bold green]Alerting setup complete![/]")
    console.print("[yellow]Note: Subscribe to the SNS topic to receive email alerts.[/]")


if __name__ == "__main__":
    main()
