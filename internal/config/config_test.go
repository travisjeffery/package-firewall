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
	if cfg.Policy.Files[0] != filepath.Join(dir, "policy.yml") {
		t.Fatalf("policy path = %q", cfg.Policy.Files[0])
	}
}

func TestValidateRejectsZeroWriteTimeout(t *testing.T) {
	cfg := Default()
	cfg.Server.WriteTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected zero write timeout to be rejected")
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
}

func TestLoadRejectsInvalidCacheEnvironmentValues(t *testing.T) {
	t.Setenv("PFW_CACHE_ARTIFACT_TTL", "not-a-duration")
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "PFW_CACHE_ARTIFACT_TTL") {
		t.Fatalf("error = %v", err)
	}
}
