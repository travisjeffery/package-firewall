package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/tidewaiter/internal/config"
	"github.com/travisjeffery/tidewaiter/internal/intel"
	"github.com/travisjeffery/tidewaiter/internal/policy"
	"github.com/travisjeffery/tidewaiter/internal/proxy"
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
	engine, err := policy.New(policy.Config{Deny: []string{"pkg:golang/golang.org/x/crypto@v1.2.3-RC1"}})
	if err != nil {
		t.Fatal(err)
	}
	provider := &criticalIntelProvider{}
	recorder := httptest.NewRecorder()
	New(cfg, engine, provider).routesHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/go/golang.org/x/crypto/@v/v1.2.3-!r!c1.mod", nil))
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
	recorder := serveAborted(t, server.routesHandler(), httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "partial" {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
	}
	metrics := httptest.NewRecorder()
	server.metrics.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `package_firewall_http_requests_total{route="npm",status="502"} 1`) {
		t.Fatalf("metrics did not classify the failed transfer:\n%s", metrics.Body.String())
	}
}

func TestServerCountsCanceledTransferAfterHeadersAs499(t *testing.T) {
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
				Body:       io.NopCloser(io.MultiReader(strings.NewReader("partial"), errorReader{err: context.Canceled})),
				Request:    request,
			}, nil
		})}),
	)
	serveAborted(t, server.routesHandler(), httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil))
	metrics := httptest.NewRecorder()
	server.metrics.Handler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), `package_firewall_http_requests_total{route="npm",status="499"} 1`) {
		t.Fatalf("metrics did not classify the canceled transfer:\n%s", metrics.Body.String())
	}
}

// Rewritten metadata streams without a Content-Length, so ending the response
// normally after an upstream failure would hand npm a cut-off packument as a whole one.
func TestServerAbortsRewrittenMetadataThatFailsMidBody(t *testing.T) {
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
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(io.MultiReader(strings.NewReader(`{"versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"}}`), failingReader{})),
				Request:    request,
			}, nil
		})}),
	)
	front := httptest.NewServer(server.routesHandler())
	defer front.Close()
	response, err := http.Get(front.URL + "/npm/pkg")
	if err != nil {
		return // the abort landed before the buffered status line was flushed
	}
	defer response.Body.Close()
	if body, err := io.ReadAll(response.Body); err == nil {
		t.Fatalf("client read a complete %d response %q from a failed upstream transfer", response.StatusCode, body)
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

func TestServerAdvertisesConfiguredAuthenticationSchemes(t *testing.T) {
	t.Setenv("PFW_TEST_CHALLENGE_BEARER", "bearer-secret")
	t.Setenv("PFW_TEST_CHALLENGE_USER", "alice")
	t.Setenv("PFW_TEST_CHALLENGE_PASS", "password")

	tests := []struct {
		name       string
		configure  func(*config.Config)
		challenges []string
	}{
		{
			name: "basic",
			configure: func(cfg *config.Config) {
				cfg.Auth.BasicUsernameEnv = "PFW_TEST_CHALLENGE_USER"
				cfg.Auth.BasicPasswordEnv = "PFW_TEST_CHALLENGE_PASS"
			},
			challenges: []string{`Basic realm="package-firewall"`},
		},
		{
			name: "bearer",
			configure: func(cfg *config.Config) {
				cfg.Auth.BearerTokenEnv = "PFW_TEST_CHALLENGE_BEARER"
			},
			challenges: []string{`Bearer realm="package-firewall"`},
		},
		{
			name: "basic and bearer",
			configure: func(cfg *config.Config) {
				cfg.Auth.BasicUsernameEnv = "PFW_TEST_CHALLENGE_USER"
				cfg.Auth.BasicPasswordEnv = "PFW_TEST_CHALLENGE_PASS"
				cfg.Auth.BearerTokenEnv = "PFW_TEST_CHALLENGE_BEARER"
			},
			challenges: []string{`Basic realm="package-firewall"`, `Bearer realm="package-firewall"`},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, err := policy.New(policy.Config{})
			if err != nil {
				t.Fatal(err)
			}
			cfg := config.Default()
			test.configure(&cfg)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
			New(cfg, engine, intel.NoopProvider{}).routesHandler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
			}
			if challenges := recorder.Header().Values("WWW-Authenticate"); !slices.Equal(challenges, test.challenges) {
				t.Fatalf("WWW-Authenticate = %q want %q", challenges, test.challenges)
			}
		})
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

// serveAborted serves a request whose body fails after the status line went out,
// requires the handler to abort it, and returns what had reached the client.
func serveAborted(t *testing.T, handler http.Handler, request *http.Request) (recorder *httptest.ResponseRecorder) {
	t.Helper()
	recorder = httptest.NewRecorder()
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want http.ErrAbortHandler", recovered)
		}
	}()
	handler.ServeHTTP(recorder, request)
	return recorder
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("upstream body read failed")
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

// The build-asset routes are fetched by the Gradle wrapper and by Docker builds
// before any authenticated setup has run, so they must answer without credentials
// while every package route stays closed.
func anonymousBuildAssetConfig(t *testing.T, upstreamURL string) config.Config {
	t.Helper()
	t.Setenv("PFW_TEST_ANON_USER", "alice")
	t.Setenv("PFW_TEST_ANON_PASS", "s3cret")
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Auth.BasicUsernameEnv = "PFW_TEST_ANON_USER"
	cfg.Auth.BasicPasswordEnv = "PFW_TEST_ANON_PASS"
	cfg.Routes = []config.RouteConfig{
		{
			Name:        "npm",
			Ecosystem:   "npm",
			PathPrefix:  "/npm/",
			UpstreamURL: upstreamURL + "/",
		},
		{
			Name:           "build-assets",
			Ecosystem:      "static",
			PathPrefix:     "/build-assets/gradle/",
			UpstreamURL:    upstreamURL + "/",
			AllowAnonymous: true,
		},
	}
	return cfg
}

func TestAnonymousRouteServesWithoutCredentials(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("zip"))
	}))
	defer upstream.Close()
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := anonymousBuildAssetConfig(t, upstream.URL)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/build-assets/gradle/gradle-9.1.0-bin.zip", nil)
	New(cfg, engine, intel.NoopProvider{}).routesHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !upstreamHit {
		t.Fatal("anonymous build-asset request never reached the upstream")
	}
}

func TestAnonymousRouteDoesNotOpenAuthenticatedRoutes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("authenticated route reached the upstream without credentials")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := anonymousBuildAssetConfig(t, upstream.URL)
	handler := New(cfg, engine, intel.NoopProvider{}).routesHandler()

	// A package route on the same server keeps its credential requirement.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/npm/lodash", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("npm status = %d body = %s", rec.Code, rec.Body.String())
	}

	// An unmatched path answers 401 rather than 404: routing now runs first, and
	// a 404 here would tell an anonymous caller which prefixes this server serves.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/build-assets/nope/x.zip", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unmatched status = %d body = %s", rec.Code, rec.Body.String())
	}
}

// A cancelled client must not be logged as a proxy failure. Package managers abort
// parallel fetches constantly, and at ERROR those lines drown out real upstream faults.
func TestServerLogsClientCancellationBelowError(t *testing.T) {
	for _, tc := range []struct {
		name          string
		upstream      error
		clientAborted bool
		wantLevel     slog.Level
		wantMsg       string
	}{
		{"client cancelled", context.Canceled, true, slog.LevelDebug, "proxy_client_disconnected"},
		{"genuine upstream failure", errors.New("dial tcp: connection refused"), false, slog.LevelError, "proxy_failed"},
		// Cache-fill coordination cancels a context derived from this request when a lease
		// renewal fails. The client is still connected, so this must stay an ERROR.
		{"internal cancellation with live client", context.Canceled, false, slog.LevelError, "proxy_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			var logs bytes.Buffer
			server.logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			server.proxy = proxy.New(
				cfg.Server.PublicBaseURL,
				proxy.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return nil, tc.upstream
				})}),
			)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
			if tc.clientAborted {
				ctx, cancel := context.WithCancel(request.Context())
				cancel()
				request = request.WithContext(ctx)
			}
			server.routesHandler().ServeHTTP(recorder, request)

			var sawWanted bool
			for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
				if line == "" {
					continue
				}
				var record map[string]any
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					t.Fatalf("log line is not JSON: %q", line)
				}
				level, _ := record["level"].(string)
				msg, _ := record["msg"].(string)
				if msg == tc.wantMsg {
					sawWanted = true
					if level != tc.wantLevel.String() {
						t.Fatalf("%s logged at %s, want %s", msg, level, tc.wantLevel)
					}
				}
				if tc.wantLevel != slog.LevelError && level == slog.LevelError.String() {
					t.Fatalf("unexpected ERROR line for a cancelled client: %q", line)
				}
			}
			if !sawWanted {
				t.Fatalf("no %q record; logs were:\n%s", tc.wantMsg, logs.String())
			}
		})
	}
}
