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

## CI Image Build

CI runs Go tests, `go vet`, and an arm64 Docker image build. On pushes to
`main`, it can also publish to ECR when these repository variables are set:

- `AWS_ROLE_ARN`
- `AWS_REGION`
- `ECR_REGISTRY`
- `ECR_REPOSITORY`

The control-plane Kubernetes deployment lives in the backend `control` Helm
chart, not in this repository.

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

- `decision.fail_open_intel_errors`: allow package downloads when OSV or another intelligence provider is unavailable.
- `decision.fail_open_unknown_package`: allow requests where the adapter cannot identify a concrete package version.
- `cache.backend`: set to `filesystem` or `s3_dynamodb` to cache exact-version package artifacts; the default `none` keeps package-firewall as a streaming proxy.
- `routes[].upstream_token_env`: injects an upstream bearer token from an environment variable without logging the secret.
- `auth.bearer_token_env` and `auth.basic_*_env`: require clients to authenticate to the firewall.

## Artifact Shielding

Artifact shielding is optional and provider-selectable:

- `none`: no persistence; package-firewall stays a streaming policy proxy.
- `filesystem`: stores cached bodies and metadata under
  `cache.filesystem.directory`. This works anywhere local disk or a mounted
  volume is available.
- `s3_dynamodb`: stores cached bodies in S3 and metadata in DynamoDB for AWS
  deployments.

Every request still goes through the normal policy and OSV decision path before
cached content is served. Fresh cache hits avoid upstream package registries;
stale exact-version artifacts can be served during upstream errors within the
configured stale window.

The filesystem backend is local to the process unless the directory is backed
by shared storage. For multi-replica deployments, use shared storage or a shared
backend such as S3/DynamoDB if cache consistency across replicas matters.

This cache does not yet cache registry metadata or share OSV results across
replicas.

## Current Limits

- No HTTPS MITM/CONNECT proxy mode.
- No package static analysis beyond local policy and OSV/feed decisions.
- No Artifactory or Nexus auto-discovery.
- PyPI file URL rewriting covers the default `files.pythonhosted.org` download host.
