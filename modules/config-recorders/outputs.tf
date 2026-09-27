output "stack_set_name" {
  description = "Name of the Config recorder StackSet."
  value       = aws_cloudformation_stack_set.config.name
}

output "target_ids" {
  description = "OU or root IDs the recorders are deployed to."
  value       = local.targets
}
