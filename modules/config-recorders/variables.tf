variable "name_prefix" {
  type        = string
  description = "Prefix for the StackSet, recorder and delivery channel names."
  default     = "sec"
}

variable "bucket_name" {
  type        = string
  description = "Config bucket in the log-archive account (log-archive module output logs_bucket_name)."
}

variable "kms_key_arn" {
  type        = string
  description = "Log-archive KMS key (log-archive module output kms_key_arn)."
}

variable "regions" {
  type        = list(string)
  description = "Regions to record in. The first is the home region, the only one that records global resources."
}

variable "target_ids" {
  type        = list(string)
  description = "OU IDs or the root ID to deploy recorders to. Empty means the organization root."
  default     = []
}

variable "recording_frequency" {
  type        = string
  description = "CONTINUOUS or DAILY."
  default     = "CONTINUOUS"

  validation {
    condition     = contains(["CONTINUOUS", "DAILY"], var.recording_frequency)
    error_message = "Use CONTINUOUS or DAILY."
  }
}

variable "include_management_account" {
  type        = bool
  description = "Also record in the management account, which service-managed StackSets never deploy to."
  default     = true
}

variable "call_as" {
  type        = string
  description = "SELF from the management account, DELEGATED_ADMIN from a StackSets delegated administrator."
  default     = "SELF"
}
