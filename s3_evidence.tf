# Evidence bucket
#
# An S3 bucket for storing audit evidence, hardened to a federal
# baseline. Each resource notes the NIST SP 800-53 Rev. 5 controls
# it supports.

variable "evidence_bucket_name" {
  description = "Globally unique name for the evidence bucket."
  type        = string
}

resource "aws_s3_bucket" "evidence" {
  #checkov:skip=CKV_AWS_144:Versioning protects against deletion; second-Region replication deferred to contingency planning. See RISK_ACCEPTANCES.md.
  #checkov:skip=CKV2_AWS_62:No event consumer exists yet; revisit when a monitoring pipeline is built. See RISK_ACCEPTANCES.md.
  bucket = var.evidence_bucket_name
}

# AC-3, SC-7: block every form of public access.
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# AC-3, AC-6: disable ACLs so only IAM policies control access.
resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SC-28: encrypt everything at rest with AWS KMS.
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# AU-9, CP-9: keep prior versions so evidence can't be silently
# overwritten or deleted.
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SC-8: reject any request that doesn't use TLS.
# AU-9: let CloudTrail and AWS Config write, and only from this account.
resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "AllowCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.evidence.arn
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
        }
      },
      {
        Sid       = "AllowConfigBucketCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.evidence.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
      {
        Sid       = "AllowConfigWrite"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/config/AWSLogs/${local.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = local.account_id
          }
        }
      },
      {
        Sid       = "AllowCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/cloudtrail/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
    ]
  })
}

# SI-12: expire replaced or deleted versions after three years, and
# clean up incomplete uploads. Current objects are never expired.
resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  depends_on = [aws_s3_bucket_versioning.evidence]

  rule {
    id     = "expire-noncurrent-versions-after-three-years"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 1095
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# AU-2, AU-12: record every request to the evidence bucket in the
# access log bucket.
resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence/"
}
