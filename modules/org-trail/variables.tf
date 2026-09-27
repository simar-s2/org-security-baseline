variable "name_prefix" {
  type        = string
  description = "Prefix for the trail name."
  default     = "sec"
}

variable "trail_name" {
  type        = string
  description = "Trail name. Null means <name_prefix>-org-trail."
  default     = null
}

variable "s3_bucket_name" {
  type        = string
  description = "CloudTrail bucket in the log-archive account (log-archive module output cloudtrail_bucket_name)."
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key that encrypts the logs (log-archive module output kms_key_arn)."
}

variable "s3_data_events" {
  type        = bool
  description = "Also log S3 object-level (data) events for every bucket in the organization. Can be expensive in busy accounts."
  default     = false
}
