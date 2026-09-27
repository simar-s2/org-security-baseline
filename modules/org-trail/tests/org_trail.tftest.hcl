mock_provider "aws" {
  override_data {
    target = data.aws_partition.current
    values = { partition = "aws" }
  }
}

variables {
  s3_bucket_name = "sec-org-cloudtrail-222233334444"
  kms_key_arn    = "arn:aws:kms:us-east-1:222233334444:key/example"
}

run "organization_wide_multi_region_trail" {
  command = plan

  assert {
    condition     = aws_cloudtrail.org.name == "sec-org-trail"
    error_message = "Default name is <prefix>-org-trail."
  }
  assert {
    condition     = aws_cloudtrail.org.is_organization_trail && aws_cloudtrail.org.is_multi_region_trail && aws_cloudtrail.org.enable_log_file_validation
    error_message = "The trail covers the whole organization, every region, with log file validation."
  }
  assert {
    condition     = length(aws_cloudtrail.org.event_selector) == 0
    error_message = "No data events by default."
  }
}

run "s3_data_events" {
  command = plan

  variables {
    s3_data_events = true
  }

  assert {
    condition     = aws_cloudtrail.org.event_selector[0].data_resource[0].values == tolist(["arn:aws:s3"])
    error_message = "Data events cover every S3 object."
  }
}
