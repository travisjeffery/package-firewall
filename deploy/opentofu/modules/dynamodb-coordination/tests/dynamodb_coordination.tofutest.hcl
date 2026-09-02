mock_provider "aws" {
  mock_resource "aws_dynamodb_table" {
    defaults = {
      arn = "arn:aws:dynamodb:us-east-1:123456789012:table/package-firewall-coordination"
    }
  }
}

run "secure_on_demand_table" {
  command = plan

  variables {
    table_name = "package-firewall-coordination"
    tags = {
      Environment = "test"
    }
  }

  assert {
    condition     = aws_dynamodb_table.this.billing_mode == "PAY_PER_REQUEST"
    error_message = "Coordination must use on-demand billing."
  }

  assert {
    condition     = aws_dynamodb_table.this.hash_key == "coordination_key"
    error_message = "The table partition key must match the runtime contract."
  }

  assert {
    condition = (
      one(aws_dynamodb_table.this.attribute).name == "coordination_key" &&
      one(aws_dynamodb_table.this.attribute).type == "S"
    )
    error_message = "The coordination key must be a string attribute."
  }

  assert {
    condition = (
      one(aws_dynamodb_table.this.ttl).enabled &&
      one(aws_dynamodb_table.this.ttl).attribute_name == "expires_at"
    )
    error_message = "TTL cleanup must use the runtime expiry attribute."
  }

  assert {
    condition     = one(aws_dynamodb_table.this.server_side_encryption).enabled
    error_message = "The coordination table must enable server-side encryption."
  }

  assert {
    condition     = aws_dynamodb_table.this.deletion_protection_enabled
    error_message = "Deletion protection must be enabled by default."
  }

  assert {
    condition     = aws_dynamodb_table.this.tags["Environment"] == "test"
    error_message = "Caller-provided tags must be applied."
  }
}

run "outputs_are_least_privilege" {
  command = plan

  variables {
    table_name = "package-firewall-coordination"
    key_prefix = "#production#"
  }

  assert {
    condition     = output.key_prefix == "production"
    error_message = "The coordination namespace must be normalized."
  }

  assert {
    condition = sort(
      jsondecode(output.runtime_iam_policy_json).Statement[0].Action
    ) == sort(["dynamodb:DeleteItem", "dynamodb:GetItem", "dynamodb:UpdateItem"])
    error_message = "Runtime IAM must grant only the operations used by coordination."
  }

  assert {
    condition     = jsondecode(output.runtime_iam_policy_json).Statement[0].Resource == output.table_arn
    error_message = "Runtime IAM must be scoped to the coordination table."
  }

  assert {
    condition = (
      output.package_firewall_environment.PFW_COORDINATION_BACKEND == "dynamodb" &&
      output.package_firewall_environment.PFW_COORDINATION_DYNAMODB_TABLE == output.table_name &&
      output.package_firewall_environment.PFW_COORDINATION_DYNAMODB_KEY_PREFIX == "production"
    )
    error_message = "Environment output must enable the selected table and namespace."
  }
}

run "allows_explicit_test_table_deletion" {
  command = plan

  variables {
    table_name                  = "package-firewall-test"
    deletion_protection_enabled = false
  }

  assert {
    condition     = !aws_dynamodb_table.this.deletion_protection_enabled
    error_message = "Explicit deletion protection override must be honored."
  }
}
