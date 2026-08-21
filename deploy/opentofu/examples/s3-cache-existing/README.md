# Attach an existing bucket

This example attaches only the package-firewall lifecycle configuration and
outputs. The module does not change any other control on the existing bucket.

`take_lifecycle_ownership = true` acknowledges that S3 has one lifecycle
configuration per bucket and that this module will replace every existing
lifecycle rule. Use a dedicated bucket if other lifecycle rules must remain.
