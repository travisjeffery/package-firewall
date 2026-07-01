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
	t.Setenv("PFW_CACHE_BACKEND", "s3_dynamodb")
	t.Setenv("PFW_CACHE_S3_BUCKET", "package-firewall-cache")
	t.Setenv("PFW_CACHE_DYNAMODB_TABLE", "package-firewall-cache")
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
	if cfg.Policy.Files[0] != filepath.Join(dir, "policy.yml") {
		t.Fatalf("policy path = %q", cfg.Policy.Files[0])
	}
	if cfg.Cache.Backend != "s3_dynamodb" {
		t.Fatalf("cache backend = %q", cfg.Cache.Backend)
	}
	if cfg.Cache.S3.Bucket != "package-firewall-cache" {
		t.Fatalf("cache bucket = %q", cfg.Cache.S3.Bucket)
	}
	if cfg.Cache.DynamoDB.Table != "package-firewall-cache" {
		t.Fatalf("cache table = %q", cfg.Cache.DynamoDB.Table)
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
