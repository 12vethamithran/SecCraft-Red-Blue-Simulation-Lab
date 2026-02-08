# Incident Response Playbook: S3 Data Exposure

## 🚨 Trigger
**Alert**: `SecurityLab-S3BucketPolicyChange` or `SecurityLab-S3PublicAccess`
**Severity**: High/Critical

## 🕵️ Analysis Steps
1.  **Identify the User**:
    - Who made the change? Check CloudTrail logs for `PutBucketPolicy` or `PutBucketAcl`.
    - Is this a known admin or a compromised user?

2.  **Review the Change**:
    - What permission was added?
    - Is `Principal: "*"` present? (Public Access)
    - Is `Action: "s3:GetObject"` allowed?

3.  **Assess Impact**:
    - List objects in the bucket.
    - Are there sensitive files (credentials, PII, secrets)?
    - Check access logs to see if external IPs accessed these files.

## 🛡️ Containment & Eradication (Remediation)
1.  **Immediate Block**:
    - Apply "Block Public Access" on the bucket immediately.
    ```python
    s3.put_public_access_block(Bucket=bucket_name, PublicAccessBlockConfiguration={...all True...})
    ```

2.  **Revert Policy**:
    - Delete the malicious bucket policy.
    ```python
    s3.delete_bucket_policy(Bucket=bucket_name)
    ```

3.  **rotate Credentials**:
    - If a user account was compromised to make this change, disable the user and rotate keys.

## 📝 Post-Incident
1.  Document the incident scope and impact.
2.  Update IAM policies to prevent users from changing bucket policies if not needed.
3.  Ensure CloudWatch alerts are functioning correctly.
