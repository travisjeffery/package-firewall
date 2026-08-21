# package-firewall S3 cache

This OpenTofu module creates a secure, unversioned S3 bucket for the
package-firewall artifact cache, or takes exclusive ownership of the lifecycle
configuration on an existing same-account bucket. It exports the application
environment and a least-privilege runtime IAM policy without creating or
attaching an IAM role or policy.

Pin the module source to a package-firewall release tag:

```hcl
module "package_firewall_cache" {
  source = "git::https://github.com/travisjeffery/package-firewall.git//deploy/opentofu/modules/s3-cache?ref=vX.Y.Z"

  bucket_name    = "company-package-firewall-cache"
  cache_prefix   = "artifacts"
  retention_days = 30

  tags = {
    Service = "package-firewall"
  }
}
```

The calling root module configures the AWS provider. This module declares its
provider requirements but does not contain a provider block or lock file.

## Existing bucket

```hcl
module "package_firewall_cache" {
  source = "git::https://github.com/travisjeffery/package-firewall.git//deploy/opentofu/modules/s3-cache?ref=vX.Y.Z"

  create_bucket             = false
  existing_bucket_name      = aws_s3_bucket.shared.id
  take_lifecycle_ownership  = true
  cache_prefix              = "package-firewall"
  retention_days            = 30

  # If this root module also manages bucket versioning, make that ordering
  # explicit:
  depends_on = [aws_s3_bucket_versioning.shared]
}
```

S3 permits only one lifecycle configuration per bucket. In existing-bucket
mode, this module replaces the bucket's complete lifecycle configuration and
removes it when the module is destroyed. It does not manage the existing
bucket's encryption, versioning, public-access settings, ownership controls,
policy, tags, or deletion. `take_lifecycle_ownership = true` is required so
this cannot happen accidentally.

Before attaching an existing bucket:

1. Inspect its current lifecycle configuration and confirm that replacing every
   rule is acceptable. Use a dedicated cache bucket if other rules must remain.
2. Remove any competing `aws_s3_bucket_lifecycle_configuration` declaration.
   If it is already in OpenTofu state, use a `moved` block to move it to
   `module.package_firewall_cache.aws_s3_bucket_lifecycle_configuration.this`,
   or import that address with the bucket name.
3. Review the plan for lifecycle-rule deletion or replacement before applying.

The module includes noncurrent-version expiration and expired-delete-marker
cleanup. These rules have no effect on an unversioned bucket, but prevent old
versions from accumulating when an attached bucket has versioning enabled or
suspended. S3 Object Lock, legal holds, and replication-pending status can
delay or prevent lifecycle deletion.

## Retention semantics

S3 lifecycle age is based on object creation or overwrite time; a `GetObject`
does not refresh it. Package-firewall's default `cache.artifact_ttl` is 24
hours. After that TTL, the next request refills and overwrites the object,
resetting its S3 lifecycle age. With the default 30-day lifecycle, an artifact
that stops being requested is therefore eligible for deletion roughly 29 to 30
days after its final use, plus S3's asynchronous lifecycle processing delay.

Always keep `retention_days` greater than `cache.artifact_ttl`. The service
treats an object removed by lifecycle as a normal cache miss and refills it
after policy and OSV evaluation.

## Outputs

Use `package_firewall_environment` to populate the workload environment. Attach
`runtime_iam_policy_json` to the workload role with the caller's preferred IAM
resource:

```hcl
resource "aws_iam_role_policy" "package_firewall_cache" {
  name   = "package-firewall-cache"
  role   = aws_iam_role.package_firewall.id
  policy = module.package_firewall_cache.runtime_iam_policy_json
}
```

The runtime policy grants only `s3:GetObject` and `s3:PutObject` under the
configured cache prefix.

## Inputs

| Name | Default | Description |
| --- | --- | --- |
| `create_bucket` | `true` | Create and secure a dedicated bucket. |
| `bucket_name` | `null` | Exact created-bucket name; null generates a `package-firewall-cache-*` name. |
| `existing_bucket_name` | `null` | Existing same-account bucket when create mode is disabled. |
| `take_lifecycle_ownership` | `false` | Required acknowledgement for existing-bucket mode. |
| `cache_prefix` | `package-firewall` | Cache object prefix; surrounding slashes are removed. |
| `retention_days` | `30` | Current-object lifetime after creation or overwrite. |
| `noncurrent_version_retention_days` | `1` | Noncurrent-version lifetime on versioned buckets. |
| `force_destroy` | `false` | Delete objects during destruction of a created bucket. |
| `tags` | `{}` | Tags applied only to a created bucket. |

With the default `force_destroy = false`, destroying a nonempty created bucket
fails until its objects have expired or are emptied separately.
