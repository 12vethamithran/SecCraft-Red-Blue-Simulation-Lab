# Attack Scenarios

## Scenario 1: S3 Bucket Enumeration
**Objective**: Find exposed sensitive data in S3 buckets.

1.  Run the enumeration tool:
    ```bash
    python penetration-testing/s3-enumeration/s3_enum.py
    ```
2.  **Observe**:
    - Which buckets are marked as "Public"?
    - Did the tool find any "SENSITIVE" files like `credentials.txt`?
3.  **Exploit**:
    - Try to download the `credentials.txt` file manually or using the AWS CLI.
    - `aws s3 cp s3://<bucket-name>/backup/credentials.txt .`

## Scenario 2: IAM Privilege Escalation
**Objective**: Escalate from a limited user to Admin.

1.  Run the escalation tool:
    ```bash
    python penetration-testing/iam-escalation/iam_escalation.py
    ```
2.  **Observe**:
    - The tool maps permissions for the current user.
    - Look for "Escalation Opportunities".
3.  **Exploit**:
    - If you see `iam:AttachUserPolicy`, you can attach `AdministratorAccess` to your own user!
    - The tool identifies this path.

## Scenario 3: EC2 SSRF & Metadata Theft
**Objective**: Steal IAM credentials using an SSRF vulnerability.

*Note: This requires access to the running EC2 instance's web app.*

1.  Run the metadata exploiter (in "Demo Mode" if local, or on the instance):
    ```bash
    python penetration-testing/ec2-metadata/ec2_metadata.py
    ```
2.  **Understand the Attack**:
    - The web app takes a URL parameter: `http://<ip>/fetch?url=...`
    - Attacker points it to: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
    - The server returns the IAM role credentials!
3.  **Impact**:
    - With these credentials (Access Key, Secret Key, Token), an attacker acts *as* that EC2 instance.
