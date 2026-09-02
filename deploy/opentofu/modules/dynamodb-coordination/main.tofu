locals {
  key_prefix = trim(trimspace(var.key_prefix), "#")

  runtime_iam_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PackageFirewallCoordination"
        Effect   = "Allow"
        Action   = ["dynamodb:DeleteItem", "dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.this.arn
      }
    ]
  }
}

resource "aws_dynamodb_table" "this" {
  name         = trimspace(var.table_name)
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "coordination_key"

  attribute {
    name = "coordination_key"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }

  deletion_protection_enabled = var.deletion_protection_enabled
  tags                        = var.tags
}
