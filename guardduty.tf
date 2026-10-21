# GuardDuty
#
# Continuously analyzes CloudTrail events, VPC flow logs, and DNS logs
# for threats: compromised credentials, crypto mining, reconnaissance,
# and calls from known malicious IP addresses.

# SI-4, IR-4: enable threat detection, publishing findings every
# 15 minutes.
resource "aws_guardduty_detector" "baseline" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

# SI-4: watch for suspicious access to S3 buckets, including the
# evidence and access log buckets.
resource "aws_guardduty_detector_feature" "s3_protection" {
  detector_id = aws_guardduty_detector.baseline.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}
