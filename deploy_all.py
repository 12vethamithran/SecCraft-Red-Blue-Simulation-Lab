"""
Deploy All Infrastructure
=========================
Master script to deploy all vulnerable infrastructure components.
"""

import sys
import os
import boto3
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import config

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()

def check_credentials():
    """Verify AWS credentials before starting"""
    try:
        boto3.client('sts').get_caller_identity()
        return True
    except Exception as e:
        console.print(Panel.fit(
            f"[bold red]Authentication Failed![/]\n"
            f"Error: {str(e)}\n\n"
            "[yellow]Troubleshooting:[/]\n"
            "1. Check your .env file credentials\n"
            "2. Ensure keys are active and not expired\n"
            "3. If using temporary credentials, check AWS_SESSION_TOKEN",
            title="Credential Error",
            border_style="red"
        ))
        return False


def main():
    console.print(Panel.fit(
        "[bold red]⚠️  AWS SECURITY LAB DEPLOYMENT  ⚠️[/]\n\n"
        "This will create:\n"
        "• Vulnerable S3 buckets (public access, no encryption)\n"
        "• Vulnerable IAM users/roles (privilege escalation paths)\n"
        "• Vulnerable EC2 instances (open security groups, IMDSv1)\n"
        "• Logging infrastructure (CloudTrail, GuardDuty)\n\n"
        "[yellow]WARNING: These resources are intentionally insecure![/]\n"
        "[yellow]Use only in a dedicated sandbox AWS account.[/]",
        title="AWS Security Lab",
        border_style="red"
    ))
    
    if not check_credentials():
        return

    if not Confirm.ask("\n[bold]Do you want to proceed with deployment?[/]"):
        console.print("[yellow]Deployment cancelled.[/]")
        return
    
    # Check for alerts definition file
    alerts_file = os.path.join(os.path.dirname(__file__), '../soc-defense/alerting-rules/cloudwatch_alerts.json')
    if not os.path.exists(alerts_file):
         console.print(f"[yellow]Warning: Alert definitions not found at {alerts_file}[/]")

    
    console.print("\n" + "="*60)
    console.print("[bold cyan]Phase 1: Setting up Logging & Detection[/]")
    console.print("="*60)
    
    from infrastructure.setup_logging import main as setup_logging
    setup_logging()
    
    console.print("\n" + "="*60)
    console.print("[bold red]Phase 2: Creating Vulnerable S3 Buckets[/]")
    console.print("="*60)
    
    from infrastructure.setup_vulnerable_s3 import main as setup_s3
    setup_s3()
    
    console.print("\n" + "="*60)
    console.print("[bold red]Phase 3: Creating Vulnerable IAM Resources[/]")
    console.print("="*60)
    
    from infrastructure.setup_vulnerable_iam import main as setup_iam
    setup_iam()
    
    console.print("\n" + "="*60)
    console.print("[bold red]Phase 4: Creating Vulnerable EC2 Resources[/]")
    console.print("="*60)
    
    from infrastructure.setup_vulnerable_ec2 import main as setup_ec2
    setup_ec2()
    
    console.print("\n" + "="*60)
    console.print("[bold cyan]Phase 5: Deploying Alerting Rules[/]")
    console.print("="*60)
    
    try:
        # Since setup_alerts.py is in a subdirectory, we might need to adjust import or path
        # Simpler approach: execute it or import directly if path allows
        # Given the structure, we can import if we add the root to path (already done)
        # Use subprocess to run the script because 'soc-defense' has a hyphen and can't be imported easily

        
        alert_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'soc-defense', 'alerting-rules', 'setup_alerts.py')
        
        if os.path.exists(alert_script):
            subprocess.run([sys.executable, alert_script], check=True)
            console.print("[green]✓ Alerts deployed[/]")
        else:
             console.print(f"[yellow]Warning: Alert script not found at {alert_script}[/]")

    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗ Alert deployment failed with exit code {e.returncode}[/]")
    except Exception as e:
        console.print(f"[yellow]Could not auto-deploy alerts: {str(e)}[/]")
        console.print("Run manually: [cyan]python soc-defense/alerting-rules/setup_alerts.py[/]")
    
    console.print("\n" + "="*60)
    console.print(Panel.fit(
        "[bold green]✓ DEPLOYMENT COMPLETE[/]\n\n"
        "Next steps:\n"
        "1. Run penetration tests: [cyan]python penetration-testing/<module>/[/]\n"
        "2. Analyze logs: [cyan]python soc-defense/log-analysis/log_analyzer.py[/]\n"
        "3. Run auto-remediation: [cyan]python soc-defense/remediation/auto_remediate.py --dry-run[/]\n"
        "4. Clean up when done: [cyan]python infrastructure/cleanup.py[/]",
        title="Success",
        border_style="green"
    ))


if __name__ == "__main__":
    main()
