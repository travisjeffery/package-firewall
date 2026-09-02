output "table_name" {
  description = "Name of the DynamoDB coordination table."
  value       = aws_dynamodb_table.this.name
}

output "table_arn" {
  description = "ARN of the DynamoDB coordination table."
  value       = aws_dynamodb_table.this.arn
}

output "key_prefix" {
  description = "Normalized namespace prefix for coordination records."
  value       = local.key_prefix
}

output "runtime_iam_policy_json" {
  description = "Least-privilege IAM policy JSON for the package-firewall runtime role. The module does not create or attach an IAM policy."
  value       = jsonencode(local.runtime_iam_policy)
}

output "package_firewall_environment" {
  description = "Environment variables required to enable package-firewall coordination."
  value = {
    PFW_COORDINATION_BACKEND             = "dynamodb"
    PFW_COORDINATION_DYNAMODB_TABLE      = aws_dynamodb_table.this.name
    PFW_COORDINATION_DYNAMODB_KEY_PREFIX = local.key_prefix
  }
}
