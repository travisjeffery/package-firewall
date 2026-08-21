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
  description = "AWS region for the package-firewall cache bucket."
  type        = string
  default     = "us-east-2"
}

module "package_firewall_cache" {
  source = "../../modules/s3-cache"

  cache_prefix   = "artifacts"
  retention_days = 30

  tags = {
    Service = "package-firewall"
  }
}

output "package_firewall_environment" {
  value = module.package_firewall_cache.package_firewall_environment
}

output "runtime_iam_policy_json" {
  value = module.package_firewall_cache.runtime_iam_policy_json
}
