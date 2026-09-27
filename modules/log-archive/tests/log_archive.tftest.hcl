mock_provider "aws" {
  # Policy documents must still be valid JSON: the provider validates policy arguments.
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}", minified_json = "{}" }
  }
  override_data {
    target = data.aws_caller_identity.current
    values = { account_id = "222233334444", arn = "arn:aws:sts::222233334444:assumed-role/Deployer/session" }
  }
  override_data {
    target = data.aws_partition.current
    values = { partition = "aws" }
  }
  override_data {
    target = data.aws_iam_session_context.current
    values = { issuer_arn = "arn:aws:iam::222233334444:role/Deployer" }
  }
}

variables {
  org_id                = "o-exampleorgid"
  management_account_id = "111122223333"
  security_account_id   = "333344445555"
  trail_name            = "sec-org-trail"
  trail_region          = "us-east-1"
}

run "bucket_names_and_lock" {
  command = plan

  assert {
    condition     = aws_s3_bucket.cloudtrail.bucket == "sec-org-cloudtrail-222233334444" && aws_s3_bucket.logs.bucket == "sec-org-logs-222233334444"
    error_message = "Bucket names are <prefix>-org-<kind>-<account ID>."
  }
  assert {
    condition     = aws_s3_bucket.cloudtrail.object_lock_enabled
    error_message = "The CloudTrail bucket must be created with Object Lock."
  }
  assert {
    condition     = aws_s3_bucket_object_lock_configuration.cloudtrail.rule[0].default_retention[0].mode == "GOVERNANCE" && aws_s3_bucket_object_lock_configuration.cloudtrail.rule[0].default_retention[0].days == 365
    error_message = "Default retention is GOVERNANCE for 365 days."
  }
  assert {
    condition     = local.trail_arn == "arn:aws:cloudtrail:us-east-1:111122223333:trail/sec-org-trail"
    error_message = "Trail ARN is built from the management account and trail name."
  }
}

run "admins_default_to_the_deployer" {
  command = plan

  assert {
    condition     = local.admins == tolist(["arn:aws:iam::222233334444:role/Deployer"])
    error_message = "The role running Terraform can keep managing bucket settings."
  }
  assert {
    condition     = tolist(local.reader_roots) == tolist(["arn:aws:iam::333344445555:root"])
    error_message = "The security account can decrypt logs by default."
  }
}

run "log_buckets_use_kms_access_logs_use_sse_s3" {
  command = plan

  assert {
    condition     = alltrue([for k, v in aws_s3_bucket_server_side_encryption_configuration.log_buckets : one(v.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms"])
    error_message = "Log buckets are encrypted with the KMS key."
  }
  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.access_logs.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    error_message = "Server access logging requires SSE-S3 on the target bucket."
  }
  assert {
    condition     = aws_kms_key.logs.enable_key_rotation
    error_message = "Key rotation is on."
  }
}

run "compliance_mode" {
  command = plan

  variables {
    object_lock_mode          = "COMPLIANCE"
    cloudtrail_retention_days = 2555
    log_expiration_days       = 2555
    reader_account_ids        = ["333344445555", "555566667777"]
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.cloudtrail.rule[0].default_retention[0].mode == "COMPLIANCE"
    error_message = "COMPLIANCE mode is passed through."
  }
  assert {
    condition     = length(local.reader_roots) == 2
    error_message = "Reader accounts are de-duplicated."
  }
}

run "expiry_shorter_than_retention_is_rejected" {
  command = plan

  variables {
    cloudtrail_retention_days = 400
    log_expiration_days       = 365
  }

  expect_failures = [aws_s3_bucket_lifecycle_configuration.log_buckets]
}

run "invalid_lock_mode" {
  command = plan

  variables {
    object_lock_mode = "STRICT"
  }

  expect_failures = [var.object_lock_mode]
}
