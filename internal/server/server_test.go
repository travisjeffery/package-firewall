package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/proxy"
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

func TestServerSkipsIntelForGoModuleMetadataButBlocksArchive(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:        "go",
		Ecosystem:   "go",
		PathPrefix:  "/go/",
		UpstreamURL: upstream.URL + "/",
	}}
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	provider := &criticalIntelProvider{}
	server := New(cfg, engine, provider).routesHandler()

	for _, extension := range []string{"info", "mod"} {
		t.Run(extension, func(t *testing.T) {
			metadata := httptest.NewRecorder()
			server.ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "/go/golang.org/x/crypto/@v/v0.0.0-20210220033148-5ea612d1eb83."+extension, nil))
			if metadata.Code != http.StatusOK {
				t.Fatalf("metadata status = %d body = %s", metadata.Code, metadata.Body.String())
			}
		})
	}
	if provider.calls != 0 || upstreamHits != 2 {
		t.Fatalf("metadata reached intel/upstream = %d/%d", provider.calls, upstreamHits)
	}

	archive := httptest.NewRecorder()
	server.ServeHTTP(archive, httptest.NewRequest(http.MethodGet, "/go/golang.org/x/crypto/@v/v0.0.0-20210220033148-5ea612d1eb83.zip", nil))
	if archive.Code != http.StatusForbidden {
		t.Fatalf("archive status = %d body = %s", archive.Code, archive.Body.String())
	}
	if provider.calls != 1 || upstreamHits != 2 {
		t.Fatalf("archive reached intel/upstream = %d/%d", provider.calls, upstreamHits)
	}
}

func TestServerAppliesPolicyToGoModuleMetadata(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:        "go",
		Ecosystem:   "go",
		PathPrefix:  "/go/",
		UpstreamURL: upstream.URL + "/",
	}}
	engine, err := policy.New(policy.Config{Deny: []string{"pkg:golang/golang.org/x/crypto@v0.0.0-20210220033148-5ea612d1eb83"}})
	if err != nil {
		t.Fatal(err)
	}
	provider := &criticalIntelProvider{}
	recorder := httptest.NewRecorder()
	New(cfg, engine, provider).routesHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/go/golang.org/x/crypto/@v/v0.0.0-20210220033148-5ea612d1eb83.mod", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	if provider.calls != 0 || upstreamHit {
		t.Fatalf("blocked metadata reached intel/upstream = %d/%v", provider.calls, upstreamHit)
	}
}

func TestServerClearsUpstreamHeadersBeforeGatewayError(t *testing.T) {
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: "https://registry.example/",
	}}
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := New(cfg, engine, intel.NoopProvider{})
	server.proxy = proxy.New(
		cfg.Server.PublicBaseURL,
		proxy.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}, "Content-Length": []string{"100"}, "ETag": []string{"upstream"}},
				Body:          io.NopCloser(failingReader{}),
				ContentLength: 100,
				Request:       request,
			}, nil
		})}),
	)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
	server.routesHandler().ServeHTTP(recorder, request)
	assertGatewayError(t, recorder, http.StatusBadGateway, "upstream_error")
	if recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", recorder.Header().Get("Content-Type"))
	}
	for _, name := range []string{"Content-Encoding", "Content-Length", "ETag"} {
		if value := recorder.Header().Get(name); value != "" {
			t.Fatalf("%s = %q", name, value)
		}
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

func TestServerReturnsBadGatewayForRejectedRedirect(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/pkg/-/pkg-1.0.0.tgz", http.StatusFound)
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:                   "npm",
		Ecosystem:              "npm",
		PathPrefix:             "/npm/",
		UpstreamURL:            upstream.URL + "/",
		EnforceRedirectOrigins: true,
	}}
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	New(cfg, engine, intel.NoopProvider{}).routesHandler().ServeHTTP(recorder, request)
	assertGatewayError(t, recorder, http.StatusBadGateway, "upstream_error")
	if targetHit {
		t.Fatal("rejected redirect target was reached")
	}
}

func TestServerReturnsGatewayTimeoutForUpstreamHeaderDeadline(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Upstream.RequestTimeout = config.Duration(200 * time.Millisecond)
	cfg.Upstream.ResponseHeaderTimeout = config.Duration(20 * time.Millisecond)
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
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	New(cfg, engine, intel.NoopProvider{}).routesHandler().ServeHTTP(recorder, request)
	assertGatewayError(t, recorder, http.StatusGatewayTimeout, "upstream_timeout")
}

func TestUpstreamQueueTimeoutMapsToServiceUnavailable(t *testing.T) {
	status, code, message := upstreamErrorResponse(proxy.ErrUpstreamQueueTimeout)
	if status != http.StatusServiceUnavailable || code != "upstream_busy" || message != "upstream request queue is full" {
		t.Fatalf("mapping = (%d, %q, %q)", status, code, message)
	}
}

func TestServerDoesNotOverwriteStartedUpstreamResponse(t *testing.T) {
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: "https://registry.example/",
	}}
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := New(cfg, engine, intel.NoopProvider{})
	server.proxy = proxy.New(
		cfg.Server.PublicBaseURL,
		proxy.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(io.MultiReader(strings.NewReader("partial"), failingReader{})),
				Request:    request,
			}, nil
		})}),
	)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	server.routesHandler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "partial" {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
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

func TestServerBlocksUnparsedNPMTarballWhenUnknownPackagesFailClosed(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodGet, "/npm/left-pad/-/left-pad-not-a-semver.tgz", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if upstreamHit {
		t.Fatal("upstream was called for unparsed npm artifact")
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

func assertGatewayError(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != wantCode || body["request_id"] == "" {
		t.Fatalf("body = %#v", body)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

type criticalIntelProvider struct {
	calls int
}

func (p *criticalIntelProvider) Query(context.Context, policy.Package) (intel.Result, error) {
	p.calls++
	return intel.Result{Findings: []intel.Finding{{ID: "GO-TEST", Severity: 10}}}, nil
}

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("upstream body read failed")
}
