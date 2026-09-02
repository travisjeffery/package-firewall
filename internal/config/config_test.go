package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadAppliesDefaultsAndEnvOverrides(t *testing.T) {
	t.Setenv("PFW_LISTEN_ADDR", ":9090")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	err := os.WriteFile(path, []byte(`
server:
  public_base_url: "http://example.test"
routes:
  - name: npm
    ecosystem: npm
    path_prefix: /npm/
    upstream_url: https://registry.npmjs.org/
policy:
  files:
    - policy.yml
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.ListenAddr != ":9090" {
		t.Fatalf("listen addr = %q", cfg.Server.ListenAddr)
	}
	if cfg.Server.ReadTimeout.Std() != 30*time.Second {
		t.Fatalf("read timeout = %s", cfg.Server.ReadTimeout.Std())
	}
	if cfg.Server.WriteTimeout.Std() != 10*time.Minute {
		t.Fatalf("write timeout = %s", cfg.Server.WriteTimeout.Std())
	}
	if cfg.Upstream.RequestTimeout.Std() != 9*time.Minute || cfg.Upstream.ResponseHeaderTimeout.Std() != 30*time.Second {
		t.Fatalf("upstream timeouts = request %s response headers %s", cfg.Upstream.RequestTimeout.Std(), cfg.Upstream.ResponseHeaderTimeout.Std())
	}
	if cfg.Upstream.MaxConcurrentPerRegistry != 4 || cfg.Upstream.QueueTimeout.Std() != 15*time.Second || cfg.Upstream.RateLimitRetries != 1 || cfg.Upstream.MaxRetryAfter.Std() != 30*time.Second {
		t.Fatalf("upstream protection defaults = %#v", cfg.Upstream)
	}
	if cfg.Cache.ReadTimeout.Std() != 30*time.Second || cfg.Cache.StoreTimeout.Std() != 10*time.Minute {
		t.Fatalf("cache timeouts = read %s store %s", cfg.Cache.ReadTimeout.Std(), cfg.Cache.StoreTimeout.Std())
	}
	if cfg.Coordination.Backend != "none" || cfg.Coordination.LeaseDuration.Std() != 30*time.Second || cfg.Coordination.PollInterval.Std() != time.Second {
		t.Fatalf("coordination defaults = %#v", cfg.Coordination)
	}
	if cfg.Policy.Files[0] != filepath.Join(dir, "policy.yml") {
		t.Fatalf("policy path = %q", cfg.Policy.Files[0])
	}
}

func TestValidateCoordination(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantError string
	}{
		{name: "dynamodb", configure: func(cfg *Config) {
			cfg.Coordination.Backend = "dynamodb"
			cfg.Coordination.DynamoDB.Table = "package-firewall"
		}},
		{name: "table required", configure: func(cfg *Config) {
			cfg.Coordination.Backend = "dynamodb"
		}, wantError: "coordination.dynamodb.table"},
		{name: "lease bounded", configure: func(cfg *Config) {
			cfg.Coordination.Backend = "dynamodb"
			cfg.Coordination.DynamoDB.Table = "package-firewall"
			cfg.Coordination.LeaseDuration = Duration(2 * time.Second)
		}, wantError: "lease_duration"},
		{name: "poll shorter than lease", configure: func(cfg *Config) {
			cfg.Coordination.Backend = "dynamodb"
			cfg.Coordination.DynamoDB.Table = "package-firewall"
			cfg.Coordination.PollInterval = cfg.Coordination.LeaseDuration
		}, wantError: "poll_interval"},
		{name: "unsupported", configure: func(cfg *Config) {
			cfg.Coordination.Backend = "redis"
		}, wantError: "unsupported"},
		{name: "filesystem cache is not shared", configure: func(cfg *Config) {
			cfg.Cache.Backend = "filesystem"
			cfg.Cache.Filesystem.Directory = "/cache"
			cfg.Coordination.Backend = "dynamodb"
			cfg.Coordination.DynamoDB.Table = "package-firewall"
		}, wantError: "replica-local filesystem cache"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.configure(&cfg)
			err := cfg.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v want substring %q", err, test.wantError)
			}
		})
	}
}

func TestLoadAppliesCoordinationEnvironmentOverrides(t *testing.T) {
	t.Setenv("PFW_COORDINATION_BACKEND", "dynamodb")
	t.Setenv("PFW_COORDINATION_LEASE_DURATION", "45s")
	t.Setenv("PFW_COORDINATION_POLL_INTERVAL", "2s")
	t.Setenv("PFW_COORDINATION_DYNAMODB_TABLE", "coordination")
	t.Setenv("PFW_COORDINATION_DYNAMODB_KEY_PREFIX", "ci")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Coordination.Backend != "dynamodb" || cfg.Coordination.LeaseDuration.Std() != 45*time.Second || cfg.Coordination.PollInterval.Std() != 2*time.Second {
		t.Fatalf("coordination config = %#v", cfg.Coordination)
	}
	if cfg.Coordination.DynamoDB.Table != "coordination" || cfg.Coordination.DynamoDB.KeyPrefix != "ci" {
		t.Fatalf("DynamoDB coordination config = %#v", cfg.Coordination.DynamoDB)
	}
}

func TestLoadAppliesUpstreamProtectionEnvironmentOverrides(t *testing.T) {
	t.Setenv("PFW_UPSTREAM_MAX_CONCURRENT_PER_REGISTRY", "7")
	t.Setenv("PFW_UPSTREAM_QUEUE_TIMEOUT", "12s")
	t.Setenv("PFW_UPSTREAM_RATE_LIMIT_RETRIES", "2")
	t.Setenv("PFW_UPSTREAM_MAX_RETRY_AFTER", "45s")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.MaxConcurrentPerRegistry != 7 || cfg.Upstream.QueueTimeout.Std() != 12*time.Second || cfg.Upstream.RateLimitRetries != 2 || cfg.Upstream.MaxRetryAfter.Std() != 45*time.Second {
		t.Fatalf("upstream protection config = %#v", cfg.Upstream)
	}
}

func TestValidateRejectsZeroWriteTimeout(t *testing.T) {
	cfg := Default()
	cfg.Server.WriteTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected zero write timeout to be rejected")
	}
}

func TestValidateUpstreamTimeouts(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		want      string
	}{
		{name: "request timeout required", configure: func(cfg *Config) {
			cfg.Upstream.RequestTimeout = 0
		}, want: "upstream.request_timeout must be positive"},
		{name: "request timeout leaves response window", configure: func(cfg *Config) {
			cfg.Upstream.RequestTimeout = cfg.Server.WriteTimeout
		}, want: "server.write_timeout must exceed the combined active"},
		{name: "request timeout leaves intelligence window", configure: func(cfg *Config) {
			cfg.Upstream.RequestTimeout = Duration(9*time.Minute + 55*time.Second)
		}, want: "server.write_timeout must exceed the combined active"},
		{name: "request timeout leaves cache read window", configure: func(cfg *Config) {
			cfg.Intel.OSV.Enabled = false
			cfg.Cache.Backend = "filesystem"
			cfg.Cache.Filesystem.Directory = "/cache"
			cfg.Cache.ReadTimeout = Duration(2 * time.Minute)
		}, want: "server.write_timeout must exceed the combined active"},
		{name: "response header timeout required", configure: func(cfg *Config) {
			cfg.Upstream.ResponseHeaderTimeout = 0
		}, want: "upstream.response_header_timeout must be positive"},
		{name: "response header timeout bounded by request", configure: func(cfg *Config) {
			cfg.Upstream.RequestTimeout = Duration(time.Minute)
			cfg.Upstream.ResponseHeaderTimeout = Duration(2 * time.Minute)
		}, want: "upstream.response_header_timeout cannot exceed upstream.request_timeout"},
		{name: "registry concurrency required", configure: func(cfg *Config) {
			cfg.Upstream.MaxConcurrentPerRegistry = 0
		}, want: "upstream.max_concurrent_per_registry must be positive"},
		{name: "queue timeout required", configure: func(cfg *Config) {
			cfg.Upstream.QueueTimeout = 0
		}, want: "upstream.queue_timeout must be positive"},
		{name: "retry count bounded", configure: func(cfg *Config) {
			cfg.Upstream.RateLimitRetries = 4
		}, want: "upstream.rate_limit_retries must be between 0 and 3"},
		{name: "retry-after bound required", configure: func(cfg *Config) {
			cfg.Upstream.MaxRetryAfter = 0
		}, want: "upstream.max_retry_after must be positive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.configure(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateTimeoutBudgetIncludesOnlyEnabledWork(t *testing.T) {
	cfg := Default()
	cfg.Intel.OSV.Enabled = false
	cfg.Upstream.RequestTimeout = Duration(9*time.Minute + 59*time.Second)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeHTTPOrigin(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: "https://CDN.example", want: "https://cdn.example:443"},
		{value: "http://registry.example:8080/", want: "http://registry.example:8080"},
		{value: "https://[2001:db8::1]", want: "https://[2001:db8::1]:443"},
	}
	for _, test := range tests {
		got, err := NormalizeHTTPOrigin(test.value)
		if err != nil {
			t.Fatalf("NormalizeHTTPOrigin(%q): %v", test.value, err)
		}
		if got != test.want {
			t.Fatalf("NormalizeHTTPOrigin(%q) = %q want %q", test.value, got, test.want)
		}
	}
	for _, value := range []string{"cdn.example", "ftp://cdn.example", "https://user@cdn.example", "https://cdn.example/files", "https://cdn.example?token=value"} {
		if _, err := NormalizeHTTPOrigin(value); err == nil {
			t.Fatalf("NormalizeHTTPOrigin(%q) succeeded", value)
		}
	}
}

func TestValidateAllowedRedirectOrigins(t *testing.T) {
	cfg := Default()
	cfg.Routes[0].AllowedRedirectOrigins = []string{"https://cdn.example"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.Routes[0].AllowedRedirectOrigins = []string{"https://cdn.example/files"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "allowed_redirect_origins") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsMissingConfiguredAuthSecrets(t *testing.T) {
	_ = os.Unsetenv("PFW_TEST_BEARER_TOKEN")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	err := os.WriteFile(path, []byte(`
server:
  public_base_url: "http://example.test"
auth:
  bearer_token_env: PFW_TEST_BEARER_TOKEN
routes:
  - name: npm
    ecosystem: npm
    path_prefix: /npm/
    upstream_url: https://registry.npmjs.org/
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded with configured missing bearer secret")
	}
}

func TestLoadRejectsPartialBasicAuthSecretConfig(t *testing.T) {
	t.Setenv("PFW_TEST_BASIC_USER", "alice")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	err := os.WriteFile(path, []byte(`
server:
  public_base_url: "http://example.test"
auth:
  basic_username_env: PFW_TEST_BASIC_USER
routes:
  - name: npm
    ecosystem: npm
    path_prefix: /npm/
    upstream_url: https://registry.npmjs.org/
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded with partial basic auth config")
	}
}

func TestValidateCacheBackends(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*Config)
		wantError string
	}{
		{name: "filesystem", configure: func(cfg *Config) {
			cfg.Cache.Backend = "filesystem"
			cfg.Cache.Filesystem.Directory = "/var/cache/package-firewall"
		}},
		{name: "filesystem directory required", configure: func(cfg *Config) {
			cfg.Cache.Backend = "filesystem"
		}, wantError: "cache.filesystem.directory"},
		{name: "s3", configure: func(cfg *Config) {
			cfg.Cache.Backend = "s3"
			cfg.Cache.S3.Bucket = "artifact-cache"
			cfg.Cache.S3.ExpectedBucketOwner = "123456789012"
		}},
		{name: "s3 bucket required", configure: func(cfg *Config) {
			cfg.Cache.Backend = "s3"
		}, wantError: "cache.s3.bucket"},
		{name: "s3 owner validated", configure: func(cfg *Config) {
			cfg.Cache.Backend = "s3"
			cfg.Cache.S3.Bucket = "artifact-cache"
			cfg.Cache.S3.ExpectedBucketOwner = "not-an-account"
		}, wantError: "12-digit AWS account ID"},
		{name: "s3 single put limit", configure: func(cfg *Config) {
			cfg.Cache.Backend = "s3"
			cfg.Cache.S3.Bucket = "artifact-cache"
			cfg.Cache.MaxObjectSize = 5_000_000_001
		}, wantError: "cannot exceed 5 GB"},
		{name: "positive ttl", configure: func(cfg *Config) {
			cfg.Cache.Backend = "filesystem"
			cfg.Cache.Filesystem.Directory = "/var/cache/package-firewall"
			cfg.Cache.ArtifactTTL = 0
		}, wantError: "cache.artifact_ttl"},
		{name: "positive object size", configure: func(cfg *Config) {
			cfg.Cache.Backend = "filesystem"
			cfg.Cache.Filesystem.Directory = "/var/cache/package-firewall"
			cfg.Cache.MaxObjectSize = 0
		}, wantError: "cache.max_object_size"},
		{name: "positive read timeout", configure: func(cfg *Config) {
			cfg.Cache.Backend = "filesystem"
			cfg.Cache.Filesystem.Directory = "/var/cache/package-firewall"
			cfg.Cache.ReadTimeout = 0
		}, wantError: "cache.read_timeout"},
		{name: "positive store timeout", configure: func(cfg *Config) {
			cfg.Cache.Backend = "filesystem"
			cfg.Cache.Filesystem.Directory = "/var/cache/package-firewall"
			cfg.Cache.StoreTimeout = 0
		}, wantError: "cache.store_timeout"},
		{name: "unsupported", configure: func(cfg *Config) {
			cfg.Cache.Backend = "dynamodb"
		}, wantError: "unsupported"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := Default()
			test.configure(&cfg)
			err := cfg.Validate()
			if test.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v want substring %q", err, test.wantError)
			}
		})
	}
}

func TestLoadAppliesCacheEnvironmentOverrides(t *testing.T) {
	t.Setenv("PFW_CACHE_BACKEND", "filesystem")
	t.Setenv("PFW_CACHE_ARTIFACT_TTL", "2h")
	t.Setenv("PFW_CACHE_MAX_OBJECT_SIZE", "4096")
	t.Setenv("PFW_CACHE_TEMP_DIRECTORY", "/tmp/pfw-stage")
	t.Setenv("PFW_CACHE_READ_TIMEOUT", "45s")
	t.Setenv("PFW_CACHE_STORE_TIMEOUT", "5m")
	t.Setenv("PFW_CACHE_FILESYSTEM_DIRECTORY", "/tmp/pfw-cache")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cache.Backend != "filesystem" || cfg.Cache.ArtifactTTL.Std() != 2*time.Hour || cfg.Cache.MaxObjectSize != 4096 {
		t.Fatalf("cache config = %#v", cfg.Cache)
	}
	if cfg.Cache.TempDirectory != "/tmp/pfw-stage" || cfg.Cache.Filesystem.Directory != "/tmp/pfw-cache" {
		t.Fatalf("cache paths = %#v", cfg.Cache)
	}
	if cfg.Cache.ReadTimeout.Std() != 45*time.Second || cfg.Cache.StoreTimeout.Std() != 5*time.Minute {
		t.Fatalf("cache timeouts = %#v", cfg.Cache)
	}
}

func TestLoadAppliesUpstreamEnvironmentOverrides(t *testing.T) {
	t.Setenv("PFW_UPSTREAM_REQUEST_TIMEOUT", "8m")
	t.Setenv("PFW_UPSTREAM_RESPONSE_HEADER_TIMEOUT", "20s")
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream.RequestTimeout.Std() != 8*time.Minute || cfg.Upstream.ResponseHeaderTimeout.Std() != 20*time.Second {
		t.Fatalf("upstream config = %#v", cfg.Upstream)
	}
}

func TestLoadRejectsInvalidUpstreamEnvironmentValues(t *testing.T) {
	for _, name := range []string{"PFW_UPSTREAM_REQUEST_TIMEOUT", "PFW_UPSTREAM_RESPONSE_HEADER_TIMEOUT"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "not-a-duration")
			if _, err := Load(""); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestLoadRejectsInvalidCacheEnvironmentValues(t *testing.T) {
	for _, name := range []string{"PFW_CACHE_ARTIFACT_TTL", "PFW_CACHE_READ_TIMEOUT", "PFW_CACHE_STORE_TIMEOUT"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "not-a-duration")
			if _, err := Load(""); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
