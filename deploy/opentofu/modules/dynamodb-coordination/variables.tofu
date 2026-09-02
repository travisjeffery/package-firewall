variable "table_name" {
  description = "Name of the DynamoDB table used for package-firewall leases and shared upstream cooldowns."
  type        = string

  validation {
    condition     = length(trimspace(var.table_name)) >= 3
    error_message = "table_name must contain at least three characters."
  }
}

variable "key_prefix" {
  description = "Namespace prefix for package-firewall coordination records in the table."
  type        = string
  default     = "package-firewall"

  validation {
    condition     = length(trim(trimspace(var.key_prefix), "#")) > 0
    error_message = "key_prefix must contain at least one non-# character."
  }
}

variable "deletion_protection_enabled" {
  description = "Whether DynamoDB deletion protection is enabled. Disable explicitly for ephemeral test environments."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Tags applied to the DynamoDB coordination table."
  type        = map(string)
  default     = {}
}
