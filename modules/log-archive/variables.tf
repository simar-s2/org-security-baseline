variable "name_prefix" {
  type        = string
  description = "Prefix for bucket names and the KMS alias."
  default     = "sec"
}

variable "org_id" {
  type        = string
  description = "AWS Organizations ID (o-...). Only services acting for this organization can write."
}

variable "management_account_id" {
  type        = string
  description = "Account that owns the organization trail."
}

variable "security_account_id" {
  type        = string
  description = "Delegated administrator account for GuardDuty and Security Hub. Its GuardDuty exports findings here, and it may decrypt the logs."
}

variable "trail_name" {
  type        = string
  description = "Name of the organization trail allowed to write to the CloudTrail bucket."
}

variable "trail_region" {
  type        = string
  description = "Region the organization trail is created in (its home region)."
}

variable "object_lock_mode" {
  type        = string
  description = "Object Lock mode for CloudTrail logs. GOVERNANCE can be lifted by a principal allowed s3:BypassGovernanceRetention (the bucket policy denies it to everyone); COMPLIANCE cannot be lifted by anyone, including the root user, until retention ends."
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.object_lock_mode)
    error_message = "Use GOVERNANCE or COMPLIANCE."
  }
}

variable "cloudtrail_retention_days" {
  type        = number
  description = "Days each CloudTrail log file is locked against deletion and overwrite."
  default     = 365
}

variable "glacier_transition_days" {
  type        = number
  description = "Days before log files move to S3 Glacier Instant Retrieval."
  default     = 90
}

variable "log_expiration_days" {
  type        = number
  description = "Days before log files expire. Must be at least cloudtrail_retention_days."
  default     = 730
}

variable "reader_account_ids" {
  type        = list(string)
  description = "Extra accounts whose IAM principals may decrypt the logs (for example to query them with Athena). The security account is always included."
  default     = []
}

variable "admin_principal_arns" {
  type        = list(string)
  description = "IAM role or user ARNs allowed to change the buckets' lifecycle, versioning, encryption and Object Lock settings. Null means the principal running Terraform. Nobody can delete log objects."
  default     = null
}
