# AWS Config in every account and region, through a service-managed StackSet
# that also enrolls accounts joining the organization later. Security Hub's
# FSBP controls are mostly Config rules, so this is what makes them work.

data "aws_organizations_organization" "this" {
  count = length(var.target_ids) == 0 ? 1 : 0
}

locals {
  template = file("${path.module}/../../cloudformation/config-recorder.yaml")
  targets  = length(var.target_ids) > 0 ? var.target_ids : [data.aws_organizations_organization.this[0].roots[0].id]

  parameters = {
    NamePrefix         = var.name_prefix
    BucketName         = var.bucket_name
    KmsKeyArn          = var.kms_key_arn
    HomeRegion         = var.regions[0]
    RecordingFrequency = var.recording_frequency
  }
}

resource "aws_cloudformation_stack_set" "config" {
  name             = "${var.name_prefix}-config-recorder"
  description      = "AWS Config recorder in every account, delivering to the log-archive account."
  permission_model = "SERVICE_MANAGED"
  capabilities     = ["CAPABILITY_IAM"]
  call_as          = var.call_as
  template_body    = local.template
  parameters       = local.parameters

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  lifecycle {
    ignore_changes = [administration_role_arn]
  }
}

resource "aws_cloudformation_stack_set_instance" "config" {
  for_each = toset(var.regions)

  stack_set_name            = aws_cloudformation_stack_set.config.name
  stack_set_instance_region = each.key
  call_as                   = var.call_as

  deployment_targets {
    organizational_unit_ids = local.targets
  }

  operation_preferences {
    max_concurrent_percentage    = 100
    failure_tolerance_percentage = 10
    region_concurrency_type      = "PARALLEL"
  }
}

resource "aws_cloudformation_stack" "management" {
  #checkov:skip=CKV_AWS_124:Deployed and watched by Terraform, which reports stack failures itself.
  for_each = var.include_management_account ? toset(var.regions) : toset([])
  region   = each.key

  name          = "${var.name_prefix}-config-recorder"
  template_body = local.template
  parameters    = local.parameters
  capabilities  = ["CAPABILITY_IAM"]
}
