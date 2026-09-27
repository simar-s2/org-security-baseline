# Organization trail, created in the management account. Every account in the
# organization, current and future, logs management events from every region
# into the log-archive bucket. Member accounts can see the trail but cannot
# stop, change or delete it.

data "aws_partition" "current" {}

locals {
  trail_name = coalesce(var.trail_name, "${var.name_prefix}-org-trail")
}

resource "aws_cloudtrail" "org" {
  #checkov:skip=CKV_AWS_252:No SNS message per log file; GuardDuty and Security Hub do the alerting.
  #checkov:skip=CKV2_AWS_10:Sending an organization trail to CloudWatch Logs is costly; the logs are queried from S3 and analyzed by GuardDuty.
  name                          = local.trail_name
  s3_bucket_name                = var.s3_bucket_name
  kms_key_id                    = var.kms_key_arn
  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  dynamic "event_selector" {
    for_each = var.s3_data_events ? [1] : []
    content {
      read_write_type           = "All"
      include_management_events = true

      data_resource {
        type   = "AWS::S3::Object"
        values = ["arn:${data.aws_partition.current.partition}:s3"]
      }
    }
  }
}
