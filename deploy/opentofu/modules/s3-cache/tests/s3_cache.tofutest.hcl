mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:user/opentofu-test"
      user_id    = "AIDATEST"
    }
  }

  mock_data "aws_partition" {
    defaults = {
      partition          = "aws"
      dns_suffix         = "amazonaws.com"
      reverse_dns_prefix = "com.amazonaws"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      id  = "package-firewall-cache-test"
      arn = "arn:aws:s3:::package-firewall-cache-test"
    }
  }
}

run "create_bucket_defaults_are_secure" {
  command = plan

  variables {
    tags = {
      Environment = "test"
    }
  }

  assert {
    condition     = length(aws_s3_bucket.this) == 1
    error_message = "Create mode must create exactly one bucket."
  }

  assert {
    condition     = aws_s3_bucket.this[0].force_destroy == false
    error_message = "Created buckets must fail safe on destroy by default."
  }

  assert {
    condition = (
      length(aws_s3_bucket.this[0].tags) == 1 &&
      aws_s3_bucket.this[0].tags["Environment"] == "test"
    )
    error_message = "Create mode must apply caller-provided tags."
  }

  assert {
    condition = (
      aws_s3_bucket_public_access_block.this[0].block_public_acls &&
      aws_s3_bucket_public_access_block.this[0].block_public_policy &&
      aws_s3_bucket_public_access_block.this[0].ignore_public_acls &&
      aws_s3_bucket_public_access_block.this[0].restrict_public_buckets
    )
    error_message = "Created buckets must block every form of public access."
  }

  assert {
    condition     = one(aws_s3_bucket_ownership_controls.this[0].rule).object_ownership == "BucketOwnerEnforced"
    error_message = "Created buckets must disable ACL ownership with BucketOwnerEnforced."
  }

  assert {
    condition = one(
      one(aws_s3_bucket_server_side_encryption_configuration.this[0].rule).apply_server_side_encryption_by_default
    ).sse_algorithm == "AES256"
    error_message = "Created buckets must explicitly use SSE-S3."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.this[0].versioning_configuration).status == "Disabled"
    error_message = "Created cache buckets must remain unversioned."
  }

  assert {
    condition = (
      jsondecode(aws_s3_bucket_policy.this[0].policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_s3_bucket_policy.this[0].policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    )
    error_message = "Created buckets must deny non-TLS requests."
  }
}

run "default_lifecycle_is_bounded" {
  command = plan

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.this.transition_default_minimum_object_size == "all_storage_classes_128K"
    error_message = "Lifecycle object-size behavior must be explicit and stable."
  }

  assert {
    condition = one(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).filter
    ).prefix == "package-firewall/"
    error_message = "Lifecycle expiration must be scoped to the cache prefix."
  }

  assert {
    condition = one(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).expiration
    ).days == 30
    error_message = "Current cache objects must expire after 30 days by default."
  }

  assert {
    condition = one(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).noncurrent_version_expiration
    ).noncurrent_days == 1
    error_message = "Noncurrent versions must expire after one day by default."
  }

  assert {
    condition = one(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).abort_incomplete_multipart_upload
    ).days_after_initiation == 1
    error_message = "Incomplete multipart uploads must be aborted after one day."
  }

  assert {
    condition = length(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).transition
    ) == 0
    error_message = "The module must not add current-object storage-class transitions."
  }

  assert {
    condition = length(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).noncurrent_version_transition
    ) == 0
    error_message = "The module must not add noncurrent storage-class transitions."
  }

  assert {
    condition = one(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expired-delete-markers"
      ]).expiration
    ).expired_object_delete_marker
    error_message = "Expired delete markers must be cleaned up by a separate rule."
  }
}

run "custom_prefix_and_retention_are_normalized" {
  command = plan

  variables {
    bucket_name                       = "company-package-firewall-cache"
    cache_prefix                      = " /nested/artifacts/ "
    retention_days                    = 45
    noncurrent_version_retention_days = 3
    force_destroy                     = true
  }

  assert {
    condition     = output.cache_prefix == "nested/artifacts"
    error_message = "Surrounding whitespace and slashes must be removed from the cache prefix."
  }

  assert {
    condition = one(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).expiration
    ).days == 45
    error_message = "Custom current-object retention must reach the lifecycle rule."
  }

  assert {
    condition = one(
      one([
        for rule in aws_s3_bucket_lifecycle_configuration.this.rule : rule
        if rule.id == "package-firewall-cache-expiration"
      ]).noncurrent_version_expiration
    ).noncurrent_days == 3
    error_message = "Custom noncurrent retention must reach the lifecycle rule."
  }

  assert {
    condition     = aws_s3_bucket.this[0].force_destroy
    error_message = "Explicit force_destroy must be honored in create mode."
  }
}

run "existing_bucket_mode_is_lifecycle_only" {
  command = plan

  variables {
    create_bucket            = false
    existing_bucket_name     = "shared-cache-bucket"
    take_lifecycle_ownership = true
    cache_prefix             = "/artifacts/"
  }

  assert {
    condition = (
      length(aws_s3_bucket.this) == 0 &&
      length(aws_s3_bucket_public_access_block.this) == 0 &&
      length(aws_s3_bucket_ownership_controls.this) == 0 &&
      length(aws_s3_bucket_server_side_encryption_configuration.this) == 0 &&
      length(aws_s3_bucket_versioning.this) == 0 &&
      length(aws_s3_bucket_policy.this) == 0
    )
    error_message = "Existing-bucket mode must not manage bucket security or deletion resources."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.this.bucket == "shared-cache-bucket"
    error_message = "Lifecycle configuration must target the supplied existing bucket."
  }

  assert {
    condition     = output.bucket_arn == "arn:aws:s3:::shared-cache-bucket"
    error_message = "Existing-bucket ARN output must use the active AWS partition."
  }

  assert {
    condition     = output.cache_object_arn == "arn:aws:s3:::shared-cache-bucket/artifacts/*"
    error_message = "Runtime access must remain scoped to the normalized cache prefix."
  }

  assert {
    condition     = output.expected_bucket_owner == "123456789012"
    error_message = "Expected owner output must use the caller's AWS account."
  }

  assert {
    condition = sort(
      jsondecode(output.runtime_iam_policy_json).Statement[0].Action
    ) == sort(["s3:GetObject", "s3:PutObject"])
    error_message = "Runtime IAM policy must grant only cache reads and writes."
  }

  assert {
    condition     = jsondecode(output.runtime_iam_policy_json).Statement[0].Resource == output.cache_object_arn
    error_message = "Runtime IAM policy must target only the configured cache prefix."
  }

  assert {
    condition = (
      output.package_firewall_environment.PFW_CACHE_BACKEND == "s3" &&
      output.package_firewall_environment.PFW_CACHE_S3_BUCKET == "shared-cache-bucket" &&
      output.package_firewall_environment.PFW_CACHE_S3_PREFIX == "artifacts" &&
      output.package_firewall_environment.PFW_CACHE_S3_EXPECTED_BUCKET_OWNER == "123456789012"
    )
    error_message = "Environment output must configure package-firewall for the selected S3 bucket."
  }
}

run "reject_existing_bucket_without_name" {
  command = plan

  variables {
    create_bucket            = false
    take_lifecycle_ownership = true
  }

  expect_failures = [aws_s3_bucket_lifecycle_configuration.this]
}

run "reject_existing_bucket_without_lifecycle_acknowledgement" {
  command = plan

  variables {
    create_bucket        = false
    existing_bucket_name = "shared-cache-bucket"
  }

  expect_failures = [aws_s3_bucket_lifecycle_configuration.this]
}

run "reject_existing_name_in_create_mode" {
  command = plan

  variables {
    existing_bucket_name = "shared-cache-bucket"
  }

  expect_failures = [aws_s3_bucket_lifecycle_configuration.this]
}

run "reject_create_only_bucket_name_in_existing_mode" {
  command = plan

  variables {
    create_bucket            = false
    bucket_name              = "new-cache-bucket"
    existing_bucket_name     = "shared-cache-bucket"
    take_lifecycle_ownership = true
  }

  expect_failures = [aws_s3_bucket_lifecycle_configuration.this]
}

run "reject_create_only_tags_in_existing_mode" {
  command = plan

  variables {
    create_bucket            = false
    existing_bucket_name     = "shared-cache-bucket"
    take_lifecycle_ownership = true
    tags = {
      Environment = "test"
    }
  }

  expect_failures = [aws_s3_bucket_lifecycle_configuration.this]
}

run "reject_force_destroy_in_existing_mode" {
  command = plan

  variables {
    create_bucket            = false
    existing_bucket_name     = "shared-cache-bucket"
    take_lifecycle_ownership = true
    force_destroy            = true
  }

  expect_failures = [aws_s3_bucket_lifecycle_configuration.this]
}

run "reject_empty_cache_prefix" {
  command = plan

  variables {
    cache_prefix = " /// "
  }

  expect_failures = [var.cache_prefix]
}

run "reject_invalid_current_retention" {
  command = plan

  variables {
    retention_days = 0
  }

  expect_failures = [var.retention_days]
}

run "reject_fractional_noncurrent_retention" {
  command = plan

  variables {
    noncurrent_version_retention_days = 1.5
  }

  expect_failures = [var.noncurrent_version_retention_days]
}
