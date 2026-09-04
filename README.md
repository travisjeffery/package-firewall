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

### Gradle cache prewarming

`pfw prewarm` discovers committed `gradle.lockfile` files, intersects them with
`gradle/verification-metadata.xml`, and downloads the resulting exact artifacts
through Package Firewall with a default concurrency of two. Active plugin marker
coordinates can be selected explicitly because Gradle does not write them to
dependency lockfiles; historical marker entries left in additive verification
metadata are not selected automatically. A configured Gradle Plugin Portal route
receives only those selected markers, while every ordinary locked artifact uses
the Maven route. Exact vendor or private coordinates can be excluded explicitly;
stale or malformed markers and exclusions fail validation. Unexpected artifacts
missing from their configured route are reported together and fail the prewarm.
The command skips source and Javadoc archives, validates every response against
the committed SHA-256 values, runs two complete passes using the same route, and
fails unless every included artifact is a cache `HIT` on the second pass.
Rate-limited responses are retried after their `Retry-After` delay, and an
optional checkpoint records completed first-pass artifacts so an interrupted
run can resume without repeating them.

Check the manifest without making network requests:

```bash
go run ./cmd/pfw prewarm --check --root ../backend
```

Warm a deployed firewall without putting a credential on the command line:

```bash
export PFW_BASE_URL=https://packages.example.com
export PACKAGE_FIREWALL_TOKEN=replace-me
go run ./cmd/pfw prewarm \
  --root ../backend \
  --plugin-route-prefix /gradle-plugins/ \
  --plugin-marker-coordinate com.example.plugin:com.example.plugin.gradle.plugin:1.2.3 \
  --exclude-coordinate com.example.vendor:private-driver:1.2.3 \
  --bearer-token-env PACKAGE_FIREWALL_TOKEN
```

For a bounded, resumable run, add `--state-file` and keep the file between
runs. `--rate-limit-retries` bounds retries after upstream `429` responses.

`--exclude-coordinate` is repeatable and accepts only a complete locked
`group:name:version`. Use it only for a dependency that the Gradle build keeps
on an external vendor or private repository. This keeps repository routing
auditable and makes a dependency version change fail closed until its source is
reviewed.

`--plugin-marker-coordinate` is repeatable and accepts only the canonical
`plugin.id:plugin.id.gradle.plugin:version` coordinate for an active plugin. The
marker must have a SHA-256-verified artifact in verification metadata, and a
Plugin Portal route must be configured when downloading it.

Use this as one controlled job before a CI traffic wave. A non-`HIT` second
pass is a failed rollout gate: it indicates disabled/failed cache storage,
insufficient cache-write settling, or an artifact path that bypasses caching.

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
- `upstream.max_concurrent_per_registry`: maximum in-flight upstream responses per registry origin on each replica.
- `upstream.queue_timeout`: maximum time a request may wait for a per-registry concurrency slot.
- `upstream.rate_limit_retries`: bounded retry count for bodyless `GET` and `HEAD` requests that receive `429`.
- `upstream.max_retry_after`: maximum cooldown a request waits inline; longer cooldowns are returned to the caller while remaining shared across replicas.
- `cache.backend`: `none`, `filesystem`, or `s3`.
- `cache.artifact_ttl`: freshness lifetime stored with each cached artifact.
- `cache.max_object_size`: maximum artifact bytes ever written to temporary cache storage.
- `cache.temp_directory`: staging directory for bounded fills and integrity-checked hits; the operating system temp directory is used when empty.
- `cache.read_timeout`: maximum time spent loading and integrity-checking a cache hit before falling back to upstream.
- `cache.store_timeout`: maximum lifetime of a background cache store after the client response completes.
- `coordination.backend`: `none` or `dynamodb`; use DynamoDB with a shared S3 cache to coalesce cold misses and share upstream cooldowns across replicas.
- `coordination.lease_duration` and `coordination.poll_interval`: bound distributed artifact-fill ownership and waiter polling.
- `decision.fail_open_intel_errors`: allow package downloads when OSV or another intelligence provider is unavailable.
- `decision.fail_open_unknown_package`: allow requests where the adapter cannot identify a concrete package version.
- `routes[].upstream_token_env`: injects an upstream bearer token from an environment variable without logging the secret.
- `routes[].enforce_redirect_origins`: opt in to keeping redirects on the original origin plus the exact origins configured for the route; disabled by default while required origins are observed.
- `routes[].allowed_redirect_origins`: exact additional HTTP(S) origins accepted when redirect-origin enforcement is enabled.
- `auth.bearer_token_env` and `auth.basic_*_env`: require clients to authenticate to the firewall.

Upstream settings can be supplied with `PFW_UPSTREAM_REQUEST_TIMEOUT`,
`PFW_UPSTREAM_RESPONSE_HEADER_TIMEOUT`,
`PFW_UPSTREAM_MAX_CONCURRENT_PER_REGISTRY`, `PFW_UPSTREAM_QUEUE_TIMEOUT`,
`PFW_UPSTREAM_RATE_LIMIT_RETRIES`, and `PFW_UPSTREAM_MAX_RETRY_AFTER`. Cache settings can be supplied with `PFW_CACHE_BACKEND`,
`PFW_CACHE_ARTIFACT_TTL`, `PFW_CACHE_MAX_OBJECT_SIZE`,
`PFW_CACHE_TEMP_DIRECTORY`, `PFW_CACHE_READ_TIMEOUT`,
`PFW_CACHE_STORE_TIMEOUT`, `PFW_CACHE_FILESYSTEM_DIRECTORY`,
`PFW_CACHE_S3_BUCKET`, `PFW_CACHE_S3_PREFIX`, and
`PFW_CACHE_S3_EXPECTED_BUCKET_OWNER`. Coordination settings can be supplied
with `PFW_COORDINATION_BACKEND`, `PFW_COORDINATION_LEASE_DURATION`,
`PFW_COORDINATION_POLL_INTERVAL`, `PFW_COORDINATION_DYNAMODB_TABLE`, and
`PFW_COORDINATION_DYNAMODB_KEY_PREFIX`.

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
- Concurrent misses for one artifact are coalesced in-process. With DynamoDB coordination enabled, one lease holder downloads and stores the artifact while other replicas poll the shared cache.
- A hit is downloaded to bounded temp storage and checked against its recorded byte count and SHA-256 before response headers or body bytes are sent. A missing, truncated, corrupt, or unreadable entry becomes an ordinary miss.
- Cache reads are bounded by `cache.read_timeout`; a slow cache becomes a clean miss instead of delaying the upstream fallback indefinitely.

Responses include `X-Package-Firewall-Cache: HIT`, `MISS`, or `BYPASS`.
The `/metrics` endpoint exports:

- `package_firewall_cache_hits_total`
- `package_firewall_cache_misses_total`
- `package_firewall_cache_store_errors_total`
- `package_firewall_cache_read_errors_total`
- `package_firewall_cache_bypasses_total{reason="..."}`
- `package_firewall_cache_fill_leaders_total`
- `package_firewall_cache_fill_waiters_total{scope="process|cluster"}`
- `package_firewall_upstream_requests_total{status="..."}`
- `package_firewall_upstream_in_flight`
- `package_firewall_upstream_retries_total{reason="rate_limited"}`
- `package_firewall_upstream_throttled_total{reason="..."}`

Bypass reasons are bounded values such as `cache_disabled`, `method`,
`not_exact_artifact`, `query`, `range`, `conditional`, `representation`,
`upstream_status`, `response_vary`, and `object_too_large`.

## AWS S3 Cache

S3 is the recommended artifact backend for multiple replicas in AWS. The
artifact objects themselves need no DynamoDB metadata: expiry, safe response
headers, byte length, and SHA-256 are stored with each S3 object. Enable the
separate DynamoDB coordinator for highly available replicas so a cold artifact
causes one upstream download rather than one per pod. Example:

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
coordination:
  backend: dynamodb
  lease_duration: 30s
  poll_interval: 1s
  dynamodb:
    table: company-package-firewall-coordination
    key_prefix: production
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

The reusable
[OpenTofu DynamoDB coordination module](deploy/opentofu/modules/dynamodb-coordination)
creates an on-demand, encrypted table with the required
`coordination_key` string partition key and `expires_at` TTL. Its environment
output and least-privilege IAM policy cover `GetItem`, `UpdateItem`, and
`DeleteItem` only:

```hcl
module "package_firewall_coordination" {
  source = "git::https://github.com/travisjeffery/package-firewall.git//deploy/opentofu/modules/dynamodb-coordination?ref=vX.Y.Z"

  table_name = "company-package-firewall-coordination"
  key_prefix = "production"
}
```

DynamoDB coordination is off the artifact-hit path. A warm S3 cache remains
available if DynamoDB is impaired; cold misses fail closed rather than starting
uncoordinated duplicate downloads. DynamoDB TTL cleanup is asynchronous, so
lease and cooldown acquisition conditions also treat expired records as
immediately reusable.

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
