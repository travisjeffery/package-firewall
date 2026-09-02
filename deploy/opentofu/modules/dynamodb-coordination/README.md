# DynamoDB coordination module

This module creates the small shared state table used to coordinate artifact
cache fills and upstream registry cooldowns across Package Firewall replicas.
The table uses on-demand billing, DynamoDB-managed multi-AZ durability,
server-side encryption, and TTL cleanup.

```hcl
module "package_firewall_coordination" {
  source = "git::https://github.com/travisjeffery/package-firewall.git//deploy/opentofu/modules/dynamodb-coordination?ref=vX.Y.Z"

  table_name = "company-package-firewall-coordination"
  key_prefix = "production"
  tags = {
    Service = "package-firewall"
  }
}
```

Attach `runtime_iam_policy_json` to the Package Firewall pod role and inject
the values in `package_firewall_environment`. The runtime uses only
`GetItem`, conditional `UpdateItem`, and conditional `DeleteItem` operations.

Deletion protection is enabled by default. The records are disposable lease
and cooldown state, so point-in-time recovery is intentionally unnecessary;
expired records are reusable immediately even if asynchronous TTL deletion has
not removed them yet.
