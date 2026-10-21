# Access log bucket
#
# Receives S3 server access logs from the evidence bucket, so every
# request to the evidence is recorded. Hardened like the evidence
# bucket, with two differences that AWS requires for log buckets:
# SSE-S3 encryption instead of KMS, and no logging of its own.

variable "access_logs_bucket_name" {
  description = "Globally unique name for the access log bucket."
  type        = string
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:AWS recommends log destination buckets not log themselves; logging this bucket would create a loop. See RISK_ACCEPTANCES.md.
  #checkov:skip=CKV_AWS_145:AWS does not support SSE-KMS on server access log destination buckets; SSE-S3 is used instead. See RISK_ACCEPTANCES.md.
  #checkov:skip=CKV_AWS_144:Same as the evidence bucket; replication deferred to contingency planning. See RISK_ACCEPTANCES.md.
  #checkov:skip=CKV2_AWS_62:No event consumer exists yet; revisit when a monitoring pipeline is built. See RISK_ACCEPTANCES.md.
  bucket = var.access_logs_bucket_name
}

# AC-3, SC-7: block every form of public access.
resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AC-3, AC-6: disable ACLs; log delivery is granted by bucket policy.
resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SC-28: encrypt at rest with S3-managed keys (the only option AWS
# supports for server access log destinations).
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# AU-9: keep prior versions so logs can't be silently altered.
resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# AU-11: retain access logs for three years, matching the evidence
# bucket, then expire them.
resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket     = aws_s3_bucket.access_logs.id
  depends_on = [aws_s3_bucket_versioning.access_logs]

  rule {
    id     = "expire-logs-after-three-years"
    status = "Enabled"

    filter {}

    expiration {
      days = 1095
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# AU-9, SC-8: allow only the S3 logging service to write logs, only
# from the evidence bucket in this account, and reject non-TLS requests.
resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3ServerAccessLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.evidence.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs.arn,
          "${aws_s3_bucket.access_logs.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}