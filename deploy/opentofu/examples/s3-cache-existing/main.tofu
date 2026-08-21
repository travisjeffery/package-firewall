terraform {
  required_version = ">= 1.8.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.59.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region containing the existing S3 bucket."
  type        = string
  default     = "us-east-2"
}

variable "existing_bucket_name" {
  description = "Existing same-account, general-purpose S3 bucket."
  type        = string
}

module "package_firewall_cache" {
  source = "../../modules/s3-cache"

  create_bucket            = false
  existing_bucket_name     = var.existing_bucket_name
  take_lifecycle_ownership = true
  cache_prefix             = "package-firewall"
  retention_days           = 30

  # If this root module manages the bucket's versioning resource, add it to a
  # module-level depends_on so lifecycle configuration follows versioning.
}

output "package_firewall_environment" {
  value = module.package_firewall_cache.package_firewall_environment
}

output "runtime_iam_policy_json" {
  value = module.package_firewall_cache.runtime_iam_policy_json
}
