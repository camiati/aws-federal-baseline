# AWS Config
#
# Records the configuration of every supported resource in the account
# and keeps a history of changes. Security Hub CSPM uses this data to
# evaluate the NIST SP 800-53 standard, so Config comes first.
#
# Snapshots and history go to the evidence bucket under the "config/"
# prefix, encrypted with the audit log KMS key.

# The service-linked role AWS recommends for the configuration recorder.
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
}

# CM-2, CM-8: record the configuration of every supported resource
# type, including global resources like IAM, to build a continuously
# updated inventory and baseline.
resource "aws_config_configuration_recorder" "baseline" {
  name     = "baseline-recorder"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# AU-9, SC-28: deliver configuration history and snapshots to the
# evidence bucket, encrypted with the audit log key.
resource "aws_config_delivery_channel" "baseline" {
  name           = "baseline-delivery"
  s3_bucket_name = aws_s3_bucket.evidence.id
  s3_key_prefix  = "config"
  s3_kms_key_arn = aws_kms_key.audit_logs.arn

  depends_on = [
    aws_config_configuration_recorder.baseline,
    aws_s3_bucket_policy.evidence,
  ]
}

# CM-3, CA-7: turn recording on. Without this, the recorder exists
# but records nothing.
resource "aws_config_configuration_recorder_status" "baseline" {
  name       = aws_config_configuration_recorder.baseline.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.baseline]
}