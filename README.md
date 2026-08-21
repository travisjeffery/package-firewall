# Package Firewall

Package Firewall is a self-hosted registry proxy that blocks risky package downloads before they reach developer machines, CI jobs, or internal mirrors.

V1 supports:

- JavaScript and TypeScript packages through npm-compatible registries.
- Python packages through the PyPI Simple API.
- Java, Kotlin, and Scala artifacts through Maven repository layout.
- Go modules through the GOPROXY protocol.

It is intentionally a registry proxy, not a TLS-intercepting proxy. Package managers point at this service directly.

## Quick Start

```bash
go test ./...
go run ./cmd/package-firewall serve --config configs/package-firewall.example.yml
```

Health checks:

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
```

Prometheus metrics are exposed at `http://localhost:8080/metrics`.

## Package Manager Configuration

```bash
npm config set registry http://localhost:8080/npm/
pip config set global.index-url http://localhost:8080/pypi/simple
export GOPROXY=http://localhost:8080/go
```

Maven example:

```xml
<settings>
  <mirrors>
    <mirror>
      <id>package-firewall</id>
      <mirrorOf>*</mirrorOf>
      <url>http://localhost:8080/maven/</url>
    </mirror>
  </mirrors>
</settings>
```

Gradle example:

```kotlin
repositories {
    maven {
        url = uri("http://localhost:8080/maven/")
    }
}
```

## Policy

Policy files use PURL-like glob rules:

```yaml
deny:
  - "pkg:npm/lodahs@*"
warn:
  - "pkg:pypi/django@5.*"
allow:
  - "pkg:golang/golang.org/x/mod@v0.30.0"
```

Explicit deny rules take precedence over allow and warn rules. Explicit allow rules skip OSV checks. Unmatched package versions are checked against OSV when enabled.

## CLI

```bash
go run ./cmd/pfw validate --config configs/package-firewall.example.yml
go run ./cmd/pfw routes --config configs/package-firewall.example.yml
go run ./cmd/pfw identify --ecosystem go --prefix /go/ --path /go/golang.org/x/mod/@v/v0.30.0.zip
go run ./cmd/pfw decide --ecosystem npm --name lodash --version 4.17.21
```

## Docker

```bash
docker build -t package-firewall .
docker compose up
```

## Live Smoke Tests

The default unit test suite does not hit public registries. To verify the
firewall against real package-manager downloads, run:

```bash
./scripts/live-smoke.sh
```

This starts a temporary local firewall and fetches pinned Kubernetes-related
dependencies through it:

- npm: `@kubernetes/client-node@0.22.3`
- PyPI: `kubernetes==29.0.0`
- Go: `k8s.io/apimachinery@v0.30.0`
- Maven: `io.kubernetes:client-java:21.0.2` POM over the Maven route

The test uses temporary package-manager caches and does not modify global npm,
pip, Go, Maven, or Gradle configuration.

It also starts a second firewall instance with a test-only deny policy and
verifies that `pkg:maven/io.kubernetes/client-java@21.0.2` returns `403` instead
of reaching Maven Central.

## Configuration

See `configs/package-firewall.example.yml`.

Important settings:

- `upstream.request_timeout`: total upstream request lifetime, including redirects and the complete response body; the server write timeout must also leave room for enabled intelligence and cache reads.
- `upstream.response_header_timeout`: maximum wait for upstream response headers.
- `cache.backend`: `none`, `filesystem`, or `s3`.
- `cache.artifact_ttl`: freshness lifetime stored with each cached artifact.
- `cache.max_object_size`: maximum artifact bytes ever written to temporary cache storage.
- `cache.temp_directory`: staging directory for bounded fills and integrity-checked hits; the operating system temp directory is used when empty.
- `cache.read_timeout`: maximum time spent loading and integrity-checking a cache hit before falling back to upstream.
- `cache.store_timeout`: maximum lifetime of a background cache store after the client response completes.
- `decision.fail_open_intel_errors`: allow package downloads when OSV or another intelligence provider is unavailable.
- `decision.fail_open_unknown_package`: allow requests where the adapter cannot identify a concrete package version.
- `routes[].upstream_token_env`: injects an upstream bearer token from an environment variable without logging the secret.
- `routes[].enforce_redirect_origins`: opt in to keeping redirects on the original origin plus the exact origins configured for the route; disabled by default while required origins are observed.
- `routes[].allowed_redirect_origins`: exact additional HTTP(S) origins accepted when redirect-origin enforcement is enabled.
- `auth.bearer_token_env` and `auth.basic_*_env`: require clients to authenticate to the firewall.

Upstream timeouts can be supplied with `PFW_UPSTREAM_REQUEST_TIMEOUT` and
`PFW_UPSTREAM_RESPONSE_HEADER_TIMEOUT`. Cache settings can be supplied with `PFW_CACHE_BACKEND`,
`PFW_CACHE_ARTIFACT_TTL`, `PFW_CACHE_MAX_OBJECT_SIZE`,
`PFW_CACHE_TEMP_DIRECTORY`, `PFW_CACHE_READ_TIMEOUT`,
`PFW_CACHE_STORE_TIMEOUT`, `PFW_CACHE_FILESYSTEM_DIRECTORY`,
`PFW_CACHE_S3_BUCKET`, `PFW_CACHE_S3_PREFIX`, and
`PFW_CACHE_S3_EXPECTED_BUCKET_OWNER`.

Cross-origin redirects are followed by default and logged as
`upstream_cross_origin_redirect` with normalized origin-only fields. Redirects
still stop after ten hops. Use these records to build a route allowlist before
enabling `enforce_redirect_origins`.

## Artifact Cache Safety

The artifact cache is deliberately narrower than a general HTTP cache:

- Authentication, package identification, local policy, and OSV-based decisions run before every cache lookup. A newly blocked package cannot be served from an old cache entry.
- Only exact package artifacts identified with a concrete name, version, and PURL are eligible. Requests must be bodyless `GET`s with no query, `Range`, conditional headers, cache-revalidation directives, cookies, or representation-selecting headers.
- Only upstream status `200` responses are stored. Redirected, ranged, encoded, `Vary`, `Set-Cookie`, `private`, `no-cache`, and `no-store` responses bypass storage.
- A miss streams the complete upstream response to the client independently of a bounded temp-file capture. The capture stops at `cache.max_object_size`; bounded backend stores continue in the background and cannot delay response completion.
- A hit is downloaded to bounded temp storage and checked against its recorded byte count and SHA-256 before response headers or body bytes are sent. A missing, truncated, corrupt, or unreadable entry becomes an ordinary miss.
- Cache reads are bounded by `cache.read_timeout`; a slow cache becomes a clean miss instead of delaying the upstream fallback indefinitely.

Responses include `X-Package-Firewall-Cache: HIT`, `MISS`, or `BYPASS`.
The `/metrics` endpoint exports:

- `package_firewall_cache_hits_total`
- `package_firewall_cache_misses_total`
- `package_firewall_cache_store_errors_total`
- `package_firewall_cache_read_errors_total`
- `package_firewall_cache_bypasses_total{reason="..."}`

Bypass reasons are bounded values such as `cache_disabled`, `method`,
`not_exact_artifact`, `query`, `range`, `conditional`, `representation`,
`upstream_status`, `response_vary`, and `object_too_large`.

## AWS S3 Cache

S3 is the recommended backend for multiple replicas in AWS. It needs no
DynamoDB table: expiry, safe response headers, byte length, and SHA-256 are
stored with each S3 object. Example:

```yaml
cache:
  backend: s3
  artifact_ttl: 24h
  max_object_size: 536870912
  temp_directory: /var/cache/package-firewall-stage
  read_timeout: 30s
  store_timeout: 10m
  s3:
    bucket: company-package-firewall-cache
    prefix: artifacts
    expected_bucket_owner: "123456789012"
```

The process uses the AWS SDK default credential chain. Set `AWS_REGION` to the
bucket's region. On EKS, use an EKS Pod Identity or IRSA-backed service account
instead of static credentials. The runtime role only needs object access under
the configured prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::company-package-firewall-cache/artifacts/*"
    }
  ]
}
```

The reusable [OpenTofu S3 cache module](deploy/opentofu/modules/s3-cache) can
create a secure bucket or attach lifecycle management to an existing bucket:

```hcl
module "package_firewall_cache" {
  source = "git::https://github.com/travisjeffery/package-firewall.git//deploy/opentofu/modules/s3-cache?ref=vX.Y.Z"

  bucket_name    = "company-package-firewall-cache"
  cache_prefix   = "artifacts"
  retention_days = 30
}
```

Pin the source to a release tag. The module exports the four `PFW_CACHE_*`
environment values and least-privilege runtime IAM policy JSON. Its default
30-day S3 lifecycle removes dependencies that are no longer refilled; keep the
lifecycle retention greater than `cache.artifact_ttl`. S3 `GetObject` calls do
not reset lifecycle age, while a refill after the default 24-hour application
TTL overwrites the object and resets its age. The module also cleans up
noncurrent versions when attached to a versioned bucket.

Attaching an existing bucket requires explicit lifecycle-ownership
acknowledgement because S3 supports only one lifecycle configuration per
bucket. See the module documentation and the
[create-new](deploy/opentofu/examples/s3-cache-create) and
[existing-bucket](deploy/opentofu/examples/s3-cache-existing) examples before
applying it.

The service treats lifecycle-expired objects as misses but does not delete them
itself. Prefer a same-region bucket and an S3 gateway endpoint for private,
lower-cost pod traffic. If the bucket uses SSE-KMS, add the corresponding
least-privilege KMS permissions.

Both cache fills and hits use local staging. Size pod `ephemeral-storage`
requests and limits for `cache.max_object_size` multiplied by expected
concurrent cache operations, or mount a dedicated volume at
`cache.temp_directory`. The S3 backend uses one atomic `PutObject`, so its
configured object limit cannot exceed 5 GB.

For local development or a single replica, use the filesystem backend:

```yaml
cache:
  backend: filesystem
  artifact_ttl: 24h
  max_object_size: 536870912
  read_timeout: 30s
  store_timeout: 10m
  filesystem:
    directory: /var/cache/package-firewall
```

## Current Limits

- No HTTPS MITM/CONNECT proxy mode.
- No package static analysis beyond local policy and OSV/feed decisions.
- No Artifactory or Nexus auto-discovery.
- PyPI file URL rewriting covers the default `files.pythonhosted.org` download host.
