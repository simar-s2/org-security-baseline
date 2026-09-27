output "kms_key_arn" {
  description = "KMS key that encrypts the CloudTrail, Config and GuardDuty logs."
  value       = aws_kms_key.logs.arn
}

output "cloudtrail_bucket_name" {
  description = "Object Lock bucket for the organization trail."
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_bucket_arn" {
  description = "ARN of the CloudTrail bucket."
  value       = aws_s3_bucket.cloudtrail.arn
}

output "logs_bucket_name" {
  description = "Bucket for AWS Config (config/ prefix) and GuardDuty findings (guardduty/ prefix)."
  value       = aws_s3_bucket.logs.id
}

output "logs_bucket_arn" {
  description = "ARN of the Config and GuardDuty bucket."
  value       = aws_s3_bucket.logs.arn
}

output "access_logs_bucket_name" {
  description = "Server access log bucket for the two log buckets."
  value       = aws_s3_bucket.access_logs.id
}

output "admin_principal_arns" {
  description = "Principals allowed to change the buckets' protective settings."
  value       = local.admins
}
