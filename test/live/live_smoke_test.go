package live_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLiveKubernetesDependencies(t *testing.T) {
	if os.Getenv("PFW_LIVE") != "1" {
		t.Skip("set PFW_LIVE=1 to run live package-manager smoke tests")
	}
	root := repoRoot(t)
	tmp := t.TempDir()
	chmodTempOnCleanup(t, tmp)
	baseURL := startFirewall(t, root, tmp, "configs/package-firewall.example.yml")

	t.Run("npm", func(t *testing.T) {
		requireTool(t, "npm")
		out := filepath.Join(tmp, "npm")
		mkdir(t, out)
		run(t, root, append(os.Environ(), "npm_config_cache="+filepath.Join(tmp, "npm-cache")),
			"npm", "pack", "@kubernetes/client-node@0.22.3",
			"--registry", baseURL+"/npm/",
			"--pack-destination", out,
		)
		assertExists(t, filepath.Join(out, "kubernetes-client-node-0.22.3.tgz"))
	})

	t.Run("pypi", func(t *testing.T) {
		requireTool(t, "python3")
		out := filepath.Join(tmp, "pip")
		mkdir(t, out)
		run(t, root, os.Environ(),
			"python3", "-m", "pip", "download", "kubernetes==29.0.0",
			"--no-deps",
			"--no-cache-dir",
			"--dest", out,
			"--index-url", baseURL+"/pypi/simple",
			"--trusted-host", "127.0.0.1",
		)
		assertExists(t, filepath.Join(out, "kubernetes-29.0.0-py2.py3-none-any.whl"))
	})

	t.Run("go", func(t *testing.T) {
		requireTool(t, "go")
		workspace := filepath.Join(tmp, "go-work")
		mkdir(t, workspace)
		run(t, workspace, os.Environ(), "go", "mod", "init", "smoke.example")
		run(t, workspace, append(os.Environ(),
			"GOPROXY="+baseURL+"/go",
			"GONOSUMDB=*",
			"GOMODCACHE="+filepath.Join(tmp, "gomodcache"),
			"GOCACHE="+filepath.Join(tmp, "gocache"),
		), "go", "mod", "download", "k8s.io/apimachinery@v0.30.0")
	})

	t.Run("maven-http", func(t *testing.T) {
		requireTool(t, "curl")
		out := filepath.Join(tmp, "client-java-21.0.2.pom")
		run(t, root, os.Environ(),
			"curl", "-fsSLo", out,
			baseURL+"/maven/io/kubernetes/client-java/21.0.2/client-java-21.0.2.pom",
		)
		assertExists(t, out)
	})
}

func TestLiveBlocksDeniedKubernetesDependency(t *testing.T) {
	if os.Getenv("PFW_LIVE") != "1" {
		t.Skip("set PFW_LIVE=1 to run live package-manager smoke tests")
	}
	requireTool(t, "curl")
	root := repoRoot(t)
	tmp := t.TempDir()
	chmodTempOnCleanup(t, tmp)
	configPath := writeDenyConfig(t, tmp)
	baseURL := startFirewall(t, root, tmp, configPath)

	resp, err := http.Get(baseURL + "/maven/io/kubernetes/client-java/21.0.2/client-java-21.0.2.pom")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "blocked") || !strings.Contains(string(body), "pkg:maven/io.kubernetes/client-java@21.0.2") {
		t.Fatalf("unexpected block body: %s", string(body))
	}
}

func startFirewall(t *testing.T, root string, tmp string, configPath string) string {
	t.Helper()
	port := freePort(t)
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	serverLog := &bytes.Buffer{}
	binary := filepath.Join(tmp, "package-firewall")
	run(t, root, os.Environ(), "go", "build", "-o", binary, "./cmd/package-firewall")
	cmd := exec.CommandContext(ctx, binary, "serve", "--config", configPath)
	cmd.Dir = root
	cmd.Stdout = serverLog
	cmd.Stderr = serverLog
	cmd.Env = append(os.Environ(),
		"PFW_LISTEN_ADDR=127.0.0.1:"+fmt.Sprint(port),
		"PFW_PUBLIC_BASE_URL="+baseURL,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start package-firewall: %v", err)
	}
	t.Cleanup(func() {
		stopProcess(cmd)
	})
	waitForHealth(t, baseURL, serverLog)
	return baseURL
}

func writeDenyConfig(t *testing.T, dir string) string {
	t.Helper()
	policyPath := filepath.Join(dir, "deny-policy.yml")
	configPath := filepath.Join(dir, "deny-config.yml")
	if err := os.WriteFile(policyPath, []byte(`deny:
  - "pkg:maven/io.kubernetes/client-java@21.0.2"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`server:
  listen_addr: ":0"
  read_timeout: 30s
  write_timeout: 0s
  shutdown_timeout: 10s
  public_base_url: "http://127.0.0.1"

decision:
  fail_open_intel_errors: false
  fail_open_unknown_package: false
  vulnerability_block_threshold: 9.0
  default_vulnerability_action: warn

intel:
  osv:
    enabled: false

policy:
  files:
    - "deny-policy.yml"

routes:
  - name: maven
    ecosystem: maven
    path_prefix: /maven/
    upstream_url: https://repo1.maven.org/maven2/
    cache_ttl: 10m
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func chmodTempOnCleanup(t *testing.T, tmp string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(tmp, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				_ = os.Chmod(path, 0o755)
			} else {
				_ = os.Chmod(path, 0o644)
			}
			return nil
		})
	})
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForHealth(t *testing.T, baseURL string, serverLog *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("package-firewall did not become healthy\n%s", serverLog.String())
}

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not found on PATH", name)
	}
}

func run(t *testing.T, dir string, env []string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, string(output))
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func assertExists(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("expected %s to be non-empty", path)
	}
}

func stopProcess(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	wait := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(wait)
	}()
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-wait:
		return
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-wait
	}
}
