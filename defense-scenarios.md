# Defense Scenarios

## Scenario 1: Log Analysis & Threat Detection
**Objective**: Detect the attacks performed in the previous phase.

1.  Run the log analyzer:
    ```bash
    python soc-defense/log-analysis/log_analyzer.py
    ```
2.  **Analyze**:
    - Look for "Suspicious Events" in the report.
    - **Reconnaissance**: Did you see `ListBuckets` or `GetCallerIdentity`?
    - **Unauthorized Access**: Are there 403 Access Denied errors?
    - **S3 Public Access**: Look for `PutBucketPolicy` or `PutBucketAcl`.

## Scenario 2: Automated Remediation
**Objective**: Fix the vulnerabilities automatically.

1.  **Dry Run**: See what *would* be fixed without changing anything.
    ```bash
    python soc-defense/remediation/auto_remediate.py --dry-run
    ```
2.  **Verified Fixes**: Run the tool to apply security controls.
    ```bash
    python soc-defense/remediation/auto_remediate.py
    ```
3.  **Verify**:
    - Go back to the AWS Console (or run attack scripts again).
    - S3 buckets should now block public access.
    - IAM users should have dangerous policies removed.
    - EC2 Security Groups should no longer allow 0.0.0.0/0.

## Scenario 3: Alerting (Bonus)
The lab sets up CloudWatch metric filters and alarms.

1.  Check `soc-defense/alerting-rules/cloudwatch_alerts.json` to see defined alerts.
2.  If you subscribed your email to the SNS topic, check your inbox!
3.  Trigger an alert by creating a new IAM user or changing a bucket policy manually.
