output "trail_arn" {
  description = "ARN of the organization trail."
  value       = aws_cloudtrail.org.arn
}

output "trail_name" {
  description = "Name of the organization trail."
  value       = aws_cloudtrail.org.name
}
