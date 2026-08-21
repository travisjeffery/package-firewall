variable "create_bucket" {
  description = "Whether the module creates and secures a dedicated S3 cache bucket. Set to false to attach lifecycle management to an existing bucket."
  type        = bool
  default     = true
}

variable "bucket_name" {
  description = "Exact bucket name in create mode. When null, a globally unique name is generated with the package-firewall-cache- prefix."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.bucket_name == null ? true : trimspace(var.bucket_name) != ""
    error_message = "bucket_name must be null or a non-empty string."
  }
}

variable "existing_bucket_name" {
  description = "Name of an existing same-account, general-purpose S3 bucket when create_bucket is false."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.existing_bucket_name == null ? true : trimspace(var.existing_bucket_name) != ""
    error_message = "existing_bucket_name must be null or a non-empty string."
  }
}

variable "take_lifecycle_ownership" {
  description = "Required acknowledgement in existing-bucket mode that this module will own and replace the bucket's complete lifecycle configuration."
  type        = bool
  default     = false
}

variable "cache_prefix" {
  description = "S3 object-key prefix reserved for package-firewall artifacts. Leading and trailing slashes are removed."
  type        = string
  default     = "package-firewall"

  validation {
    condition     = length(trim(trimspace(var.cache_prefix), "/")) > 0
    error_message = "cache_prefix must contain at least one non-slash character."
  }
}

variable "retention_days" {
  description = "Days after the last object creation or overwrite before S3 expires a current cache object. Keep this greater than package-firewall's cache.artifact_ttl."
  type        = number
  default     = 30

  validation {
    condition     = var.retention_days > 0 && floor(var.retention_days) == var.retention_days
    error_message = "retention_days must be a positive integer."
  }
}

variable "noncurrent_version_retention_days" {
  description = "Days to retain a noncurrent object version on an existing versioned bucket."
  type        = number
  default     = 1

  validation {
    condition     = var.noncurrent_version_retention_days > 0 && floor(var.noncurrent_version_retention_days) == var.noncurrent_version_retention_days
    error_message = "noncurrent_version_retention_days must be a positive integer."
  }
}

variable "force_destroy" {
  description = "Whether OpenTofu may delete all cached objects when destroying a module-created bucket. Valid only in create mode."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags for a module-created bucket. Existing-bucket mode deliberately does not manage bucket tags."
  type        = map(string)
  default     = {}
}
