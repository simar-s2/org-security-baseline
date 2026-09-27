mock_provider "aws" {
  override_data {
    target = data.aws_organizations_organization.this
    values = { roots = [{ id = "r-ab12", arn = "arn:aws:organizations::111122223333:root/o-exampleorgid/r-ab12", name = "Root", policy_types = [] }] }
  }
}

variables {
  bucket_name = "sec-org-logs-222233334444"
  kms_key_arn = "arn:aws:kms:us-east-1:222233334444:key/example"
  regions     = ["us-east-1", "us-west-2"]
}

run "defaults_to_the_whole_organization" {
  command = plan

  assert {
    condition     = tolist(local.targets) == tolist(["r-ab12"])
    error_message = "With no targets, recorders go to every account under the root."
  }
  assert {
    condition     = toset(keys(aws_cloudformation_stack_set_instance.config)) == toset(["us-east-1", "us-west-2"])
    error_message = "One StackSet instance per region."
  }
  assert {
    condition     = aws_cloudformation_stack_set.config.parameters["HomeRegion"] == "us-east-1"
    error_message = "The first region records global resources."
  }
  assert {
    condition     = length(aws_cloudformation_stack.management) == 2
    error_message = "The management account records too."
  }
}

run "explicit_targets_skip_the_lookup" {
  command = plan

  variables {
    target_ids                 = ["ou-ab12-11111111"]
    include_management_account = false
    recording_frequency        = "DAILY"
  }

  assert {
    condition     = length(data.aws_organizations_organization.this) == 0 && tolist(local.targets) == tolist(["ou-ab12-11111111"])
    error_message = "Explicit targets are used as given."
  }
  assert {
    condition     = length(aws_cloudformation_stack.management) == 0
    error_message = "Management account stacks are optional."
  }
  assert {
    condition     = aws_cloudformation_stack_set.config.parameters["RecordingFrequency"] == "DAILY"
    error_message = "Recording frequency is passed to the template."
  }
}
