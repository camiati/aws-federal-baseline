# Customer-managed KMS key for audit logs
#
# Encrypts CloudTrail logs and AWS Config deliveries with a key this account controls, so reading
# the logs requires both S3 and KMS permissions. Rotated automatically.
#
# ARNs are built with the current partition, so the same code works in
# commercial Regions ("aws") and GovCloud ("aws-us-gov").

data "aws_partition" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "baseline-trail"
  trail_arn  = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
}

# SC-12, SC-13: a customer-managed key with automatic yearly rotation.
resource "aws_kms_key" "audit_logs" {
  description             = "ncrypts CloudTrail and AWS Config audit data"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncryptLogs"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*" }
        }
      },
            {
        Sid       = "AllowConfigEncryptDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
      {
        Sid       = "AllowCloudTrailDescribeKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "audit_logs" {
  name          = "alias/audit-logs"
  target_key_id = aws_kms_key.audit_logs.key_id
}
