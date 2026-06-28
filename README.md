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

## Configuration

See `configs/package-firewall.example.yml`.

Important settings:

- `decision.fail_open_intel_errors`: allow package downloads when OSV or another intelligence provider is unavailable.
- `decision.fail_open_unknown_package`: allow requests where the adapter cannot identify a concrete package version.
- `routes[].upstream_token_env`: injects an upstream bearer token from an environment variable without logging the secret.
- `auth.bearer_token_env` and `auth.basic_*_env`: require clients to authenticate to the firewall.

## Current Limits

- No HTTPS MITM/CONNECT proxy mode.
- No package static analysis beyond local policy and OSV/feed decisions.
- No Artifactory or Nexus auto-discovery.
- PyPI file URL rewriting covers the default `files.pythonhosted.org` download host.
