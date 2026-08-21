data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  normalized_cache_prefix = trim(trimspace(var.cache_prefix), "/")
  existing_bucket_name    = var.existing_bucket_name == null ? "" : trimspace(var.existing_bucket_name)

  bucket_name      = var.create_bucket ? one(aws_s3_bucket.this[*].bucket) : local.existing_bucket_name
  bucket_arn       = var.create_bucket ? one(aws_s3_bucket.this[*].arn) : "arn:${data.aws_partition.current.partition}:s3:::${local.existing_bucket_name}"
  cache_object_arn = "${local.bucket_arn}/${local.normalized_cache_prefix}/*"

  runtime_iam_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PackageFirewallCacheObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = local.cache_object_arn
      }
    ]
  }
}

resource "aws_s3_bucket" "this" {
  count = var.create_bucket ? 1 : 0

  bucket        = var.bucket_name
  bucket_prefix = var.bucket_name == null ? "package-firewall-cache-" : null
  force_destroy = var.force_destroy
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_policy" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.this[0].arn,
          "${aws_s3_bucket.this[0].arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.this]
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = local.bucket_name

  transition_default_minimum_object_size = "all_storage_classes_128K"

  rule {
    id     = "package-firewall-cache-expiration"
    status = "Enabled"

    filter {
      prefix = "${local.normalized_cache_prefix}/"
    }

    expiration {
      days = var.retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "package-firewall-cache-expired-delete-markers"
    status = "Enabled"

    filter {
      prefix = "${local.normalized_cache_prefix}/"
    }

    expiration {
      expired_object_delete_marker = true
    }
  }

  lifecycle {
    precondition {
      condition = var.create_bucket ? var.existing_bucket_name == null : (
        var.existing_bucket_name == null ? false : trimspace(var.existing_bucket_name) != ""
      )
      error_message = "Set exactly one bucket mode: create_bucket=true without existing_bucket_name, or create_bucket=false with existing_bucket_name."
    }

    precondition {
      condition     = var.create_bucket || var.take_lifecycle_ownership
      error_message = "Existing-bucket mode requires take_lifecycle_ownership=true because S3 supports only one lifecycle configuration per bucket."
    }

    precondition {
      condition     = var.create_bucket || var.bucket_name == null
      error_message = "bucket_name is valid only when create_bucket=true."
    }

    precondition {
      condition     = var.create_bucket || length(var.tags) == 0
      error_message = "tags are valid only when create_bucket=true; existing-bucket mode does not manage bucket tags."
    }

    precondition {
      condition     = var.create_bucket || !var.force_destroy
      error_message = "force_destroy is valid only when create_bucket=true."
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}
