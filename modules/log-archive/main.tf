# Central log archive, deployed in the log-archive account.
#
#   <prefix>-org-cloudtrail-<account>  organization trail. Object Lock with
#                                      default retention: no one can delete or
#                                      overwrite a log file until it expires.
#   <prefix>-org-logs-<account>        AWS Config (config/) and GuardDuty
#                                      findings (guardduty/). Versioned, and the
#                                      bucket policy denies every delete. No
#                                      Object Lock default retention, because
#                                      AWS Config cannot deliver to such a bucket.
#   <prefix>-s3-access-logs-<account>  server access logs for both buckets.
#
# Both log buckets use one customer managed KMS key. Only the CloudTrail, Config
# and GuardDuty services, acting for this organization, can write.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  trail_arn    = "arn:${local.partition}:cloudtrail:${var.trail_region}:${var.management_account_id}:trail/${var.trail_name}"
  admins       = coalesce(var.admin_principal_arns, [data.aws_iam_session_context.current.issuer_arn])
  reader_roots = [for id in distinct(concat([var.security_account_id], var.reader_account_ids)) : "arn:${local.partition}:iam::${id}:root"]

  buckets = {
    cloudtrail  = "${var.name_prefix}-org-cloudtrail-${local.account_id}"
    logs        = "${var.name_prefix}-org-logs-${local.account_id}"
    access_logs = "${var.name_prefix}-s3-access-logs-${local.account_id}"
  }
}

# ---------------------------------------------------------------- KMS key

data "aws_iam_policy_document" "key" {
  #checkov:skip=CKV_AWS_109:Key policies must use "*" as the resource; access is limited by principals and conditions.
  #checkov:skip=CKV_AWS_111:Key policies must use "*" as the resource; access is limited by principals and conditions.
  #checkov:skip=CKV_AWS_356:Key policies must use "*" as the resource; access is limited by principals and conditions.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncrypt"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${var.management_account_id}:trail/*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailDescribeKey"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  statement {
    sid       = "ConfigEncrypt"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [var.org_id]
    }
  }

  statement {
    sid       = "GuardDutyEncrypt"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }

  statement {
    sid       = "ReadersDecrypt"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = local.reader_roots
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "Encrypts the organization's CloudTrail, Config and GuardDuty logs"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.key.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-org-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# ---------------------------------------------------------------- buckets

resource "aws_s3_bucket" "cloudtrail" {
  #checkov:skip=CKV_AWS_144:Object Lock and deny-delete protect the only copy; replicate if your policy requires a second region.
  #checkov:skip=CKV2_AWS_62:Nothing consumes object events; logs are queried on demand.
  bucket              = local.buckets.cloudtrail
  object_lock_enabled = true
}

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_144:Deny-delete protects the only copy; replicate if your policy requires a second region.
  #checkov:skip=CKV2_AWS_62:Nothing consumes object events; logs are queried on demand.
  bucket = local.buckets.logs
}

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This is the access-log destination; logging it to itself would loop.
  #checkov:skip=CKV_AWS_144:Access logs are secondary evidence; a second copy is not worth the cost.
  #checkov:skip=CKV2_AWS_62:Nothing consumes object events.
  #checkov:skip=CKV_AWS_145:S3 server access logging can only deliver to buckets encrypted with SSE-S3.
  bucket = local.buckets.access_logs
}

locals {
  log_buckets = {
    cloudtrail = aws_s3_bucket.cloudtrail
    logs       = aws_s3_bucket.logs
  }
  all_buckets = merge(local.log_buckets, { access_logs = aws_s3_bucket.access_logs })
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.all_buckets
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = local.all_buckets
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = local.all_buckets
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_buckets" {
  for_each = local.log_buckets
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_object_lock_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.cloudtrail_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_logging" "this" {
  for_each      = local.log_buckets
  bucket        = each.value.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "${each.value.id}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "log_buckets" {
  for_each = local.log_buckets
  bucket   = each.value.id

  rule {
    id     = "archive-then-expire"
    status = "Enabled"
    filter {}

    transition {
      days          = var.glacier_transition_days
      storage_class = "GLACIER_IR"
    }
    # Expiry adds a delete marker; the locked version itself is removed by the
    # noncurrent rule only after its retention has ended.
    expiration {
      days = var.log_expiration_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  lifecycle {
    precondition {
      condition     = var.log_expiration_days >= var.cloudtrail_retention_days
      error_message = "log_expiration_days must be at least cloudtrail_retention_days."
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire"
    status = "Enabled"
    filter {}

    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

# ---------------------------------------------------------------- bucket policies

# Statements shared by both log buckets: TLS only, no deletes by anyone, and
# only the admins may change the settings that protect the data.
data "aws_iam_policy_document" "protect" {
  for_each = local.log_buckets

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value.arn, "${each.value.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyDelete"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention", "s3:DeleteBucket"]
    resources = [each.value.arn, "${each.value.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }

  statement {
    sid    = "DenyProtectionChanges"
    effect = "Deny"
    actions = [
      "s3:PutBucketObjectLockConfiguration",
      "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration",
      "s3:PutEncryptionConfiguration",
      "s3:PutBucketLogging",
    ]
    resources = [each.value.arn]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalArn"
      values   = local.admins
    }
  }
}

data "aws_iam_policy_document" "cloudtrail" {
  source_policy_documents = [data.aws_iam_policy_document.protect["cloudtrail"].json]

  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid     = "CloudTrailWrite"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${var.management_account_id}/*",
      "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${var.org_id}/*",
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

data "aws_iam_policy_document" "logs" {
  source_policy_documents = [data.aws_iam_policy_document.protect["logs"].json]

  statement {
    sid       = "ConfigBucketCheck"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [var.org_id]
    }
  }

  statement {
    sid       = "ConfigWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/config/AWSLogs/*/Config/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceOrgID"
      values   = [var.org_id]
    }
  }

  statement {
    sid       = "GuardDutyBucketCheck"
    actions   = ["s3:GetBucketLocation"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }

  statement {
    sid       = "GuardDutyWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/guardduty/*"]
    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid       = "ServerAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/*"]
    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.cloudtrail.arn, aws_s3_bucket.logs.arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket     = aws_s3_bucket.cloudtrail.id
  policy     = data.aws_iam_policy_document.cloudtrail.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_policy" "logs" {
  bucket     = aws_s3_bucket.logs.id
  policy     = data.aws_iam_policy_document.logs.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket     = aws_s3_bucket.access_logs.id
  policy     = data.aws_iam_policy_document.access_logs.json
  depends_on = [aws_s3_bucket_public_access_block.this]
}
