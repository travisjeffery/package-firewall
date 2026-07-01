package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
)

func TestServerBlocksDeniedArtifactBeforeUpstream(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: upstream.URL + "/",
	}}
	engine, err := policy.New(policy.Config{Deny: []string{"pkg:npm/lodahs@*"}})
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, engine, intel.NoopProvider{}).routesHandler()
	req := httptest.NewRequest(http.MethodGet, "/npm/lodahs/-/lodahs-1.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if upstreamHit {
		t.Fatal("upstream was called for blocked artifact")
	}
}

func TestServerSupportsNPMRootTarballFallback(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/is-number/-/is-number-7.0.0.tgz" {
			t.Fatalf("unexpected upstream path %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: upstream.URL + "/",
	}}
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, engine, intel.NoopProvider{}).routesHandler()
	req := httptest.NewRequest(http.MethodGet, "/is-number/-/is-number-7.0.0.tgz", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestServerBlocksUnparsedPyPIFileWhenUnknownPackagesFailClosed(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Decision.FailOpenUnknownPackage = false
	cfg.Routes = []config.RouteConfig{{
		Name:            "pypi",
		Ecosystem:       "pypi",
		PathPrefix:      "/pypi/",
		UpstreamURL:     "https://pypi.example/",
		FileUpstreamURL: upstream.URL + "/",
	}}
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, engine, intel.NoopProvider{}).routesHandler()
	req := httptest.NewRequest(http.MethodGet, "/pypi/files/packages/left_pad-not-a-version.whl", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if upstreamHit {
		t.Fatal("file upstream was called for unparsed pypi artifact")
	}
}

func TestRunHealthEndpoint(t *testing.T) {
	cfg := config.Default()
	cfg.Server.ListenAddr = "127.0.0.1:0"
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = Run(ctx, cfg, engine, intel.NoopProvider{})
}

func TestConfiguredMissingBearerDeniesRequests(t *testing.T) {
	_ = os.Unsetenv("PFW_TEST_MISSING_BEARER")
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.BearerTokenEnv = "PFW_TEST_MISSING_BEARER"
	s := New(cfg, engine, intel.NoopProvider{})
	if s.authorized(httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)) {
		t.Fatal("configured missing bearer secret authorized request")
	}
}

func TestPartialBasicSecretDoesNotAcceptEmptyPeer(t *testing.T) {
	t.Setenv("PFW_TEST_BASIC_USER", "alice")
	_ = os.Unsetenv("PFW_TEST_BASIC_PASS")
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.BasicUsernameEnv = "PFW_TEST_BASIC_USER"
	cfg.Auth.BasicPasswordEnv = "PFW_TEST_BASIC_PASS"
	s := New(cfg, engine, intel.NoopProvider{})
	req := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
	req.SetBasicAuth("alice", "")
	if s.authorized(req) {
		t.Fatal("partial basic secret authorized empty password")
	}
}
