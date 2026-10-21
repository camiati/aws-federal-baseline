# CloudTrail
#
# Records every management API call in every Region: who did what,
# when, and from where. Logs go to the evidence bucket under the
# "cloudtrail/" prefix, encrypted with the audit log KMS key.

# AU-2, AU-3, AU-12: record management events in all Regions.
# AU-9: log file validation detects altered or deleted log files.
# SC-28: logs encrypted with the customer-managed audit log key.
resource "aws_cloudtrail" "baseline" {
  #checkov:skip=CKV_AWS_252:Per-file delivery notifications aren't actionable; alerting comes from GuardDuty and Security Hub. See RISK_ACCEPTANCES.md.
  #checkov:skip=CKV2_AWS_10:Planned remediation, not an acceptance: CloudWatch Logs integration in the monitoring pull request, target QX YYYY. See RISK_ACCEPTANCES.md.
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.evidence.id
  s3_key_prefix                 = "cloudtrail"
  kms_key_id                    = aws_kms_key.audit_logs.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.evidence]
}
