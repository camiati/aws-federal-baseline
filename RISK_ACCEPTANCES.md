# Risk Acceptances

Security checks this repo deliberately does not meet, with the reasoning, the controls affected, and when each decision will be revisited.

Each acceptance is enforced in code with a `#checkov:skip` comment inside the affected resource. Checkov reports these as **Skipped** on every scan, with the justification shown in the log. Removing a skip comment makes the check fail again.

## Current acceptances

| Check | Resource | Justification | Controls | Accepted | Review by |
|---|---|---|---|---|---|
| CKV_AWS_144: cross&#8209;region replication | `aws_s3_bucket.evidence`, `aws_s3_bucket.access_logs` | Versioning already protects against deletion. Whether evidence and logs need a second Region is a contingency planning decision, not a default. | CP&#8209;6, CP&#8209;9 | Oct 2026 | Apr 2027 |
| CKV2_AWS_62: event notifications | `aws_s3_bucket.evidence`, `aws_s3_bucket.access_logs` | Notifications only matter if something consumes them, and no monitoring pipeline exists yet. | AU&#8209;6, SI&#8209;4 | Oct 2026 | Apr 2027 |
| CKV_AWS_18: access logging | `aws_s3_bucket.access_logs` | This bucket receives the evidence bucket's access logs. AWS recommends that log destination buckets not log themselves, which would create a loop. Object-level access to the logs can be recorded with CloudTrail data events once CloudTrail is added. | AU&#8209;2, AU&#8209;12 | Oct 2026 | Apr 2027 |
| CKV_AWS_145: KMS encryption | `aws_s3_bucket.access_logs` | AWS does not support SSE-KMS default encryption on server access log destination buckets ([AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/troubleshooting-server-access-logging.html)). The bucket uses SSE-S3 (AES-256) instead, so data is still encrypted at rest. | SC&#8209;28 | Oct 2026 | Apr 2027 |

## Process

1. **Decide:** a failing check is either fixed or accepted. Accepting requires a written justification.
2. **Enforce:** add a `#checkov:skip=CHECK_ID:justification` comment inside the resource.
3. **Record:** add a row to the table above, with the controls affected and a review date no more than six months out.
4. **Approve:** make the change through a pull request, so the decision has an author, a timestamp, and a review.
5. **Revisit:** on or before the review date, either renew the acceptance with an updated justification or fix the finding and remove the skip.

## Closed acceptances

None yet. When an acceptance is resolved, move its row here with the date and how it was closed.