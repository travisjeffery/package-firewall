package config

import (
	"os"
	"path/filepath"
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
