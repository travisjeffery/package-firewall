# Create a cache bucket

This example lets the module create an unversioned, SSE-S3-encrypted cache
bucket with public access blocked and a TLS-only bucket policy.

For real use, pin the module to a package-firewall release instead of using the
repository-relative source shown in `main.tofu`.
