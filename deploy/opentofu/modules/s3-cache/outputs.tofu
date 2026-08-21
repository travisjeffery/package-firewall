output "bucket_name" {
  description = "Name of the created or attached S3 cache bucket."
  value       = local.bucket_name
}

output "bucket_arn" {
  description = "ARN of the created or attached S3 cache bucket."
  value       = local.bucket_arn
}

output "cache_prefix" {
  description = "Normalized package-firewall cache object-key prefix."
  value       = local.normalized_cache_prefix
}

output "cache_object_arn" {
  description = "ARN matching only package-firewall cache objects under the configured prefix."
  value       = local.cache_object_arn
}

output "expected_bucket_owner" {
  description = "AWS account ID to configure as package-firewall's expected S3 bucket owner."
  value       = data.aws_caller_identity.current.account_id
}

output "runtime_iam_policy_json" {
  description = "Least-privilege IAM policy JSON for the package-firewall runtime role. The module does not create or attach an IAM policy."
  value       = jsonencode(local.runtime_iam_policy)
}

output "package_firewall_environment" {
  description = "Environment variables required to select and configure package-firewall's S3 cache backend."
  value = {
    PFW_CACHE_BACKEND                  = "s3"
    PFW_CACHE_S3_BUCKET                = local.bucket_name
    PFW_CACHE_S3_PREFIX                = local.normalized_cache_prefix
    PFW_CACHE_S3_EXPECTED_BUCKET_OWNER = data.aws_caller_identity.current.account_id
  }
}
