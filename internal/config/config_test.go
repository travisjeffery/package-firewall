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
	t.Setenv("PFW_CACHE_BACKEND", "filesystem")
	t.Setenv("PFW_CACHE_FILESYSTEM_DIRECTORY", filepath.Join(t.TempDir(), "cache"))
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
	if cfg.Cache.Backend != "filesystem" {
		t.Fatalf("cache backend = %q", cfg.Cache.Backend)
	}
	if cfg.Cache.Filesystem.Directory == "" {
		t.Fatal("cache filesystem directory was not set")
	}
}

func TestLoadRejectsFilesystemCacheWithoutDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	err := os.WriteFile(path, []byte(`
server:
  public_base_url: "http://example.test"
cache:
  backend: filesystem
routes:
  - name: npm
    ecosystem: npm
    path_prefix: /npm/
    upstream_url: https://registry.npmjs.org/
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	if err == nil {
		t.Fatal("expected filesystem cache validation error")
	}
	if !strings.Contains(err.Error(), "cache.filesystem.directory is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsS3DynamoDBCacheWithoutResources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	err := os.WriteFile(path, []byte(`
server:
  public_base_url: "http://example.test"
cache:
  backend: s3_dynamodb
routes:
  - name: npm
    ecosystem: npm
    path_prefix: /npm/
    upstream_url: https://registry.npmjs.org/
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Load(path)
	if err == nil {
		t.Fatal("expected cache resource validation error")
	}
	if !strings.Contains(err.Error(), "cache.s3.bucket is required") {
		t.Fatalf("error = %v", err)
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
