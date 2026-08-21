package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/artifactcache"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/proxy"
)

func TestPolicyAndIntelRunBeforeEveryCacheHit(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	engine, err := policy.New(policy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	provider := &countingIntelProvider{}
	store := &repeatingHitStore{body: []byte("cached-artifact")}
	server := New(
		testCacheServerConfig(upstream.URL),
		engine,
		provider,
		proxy.CacheConfig{
			Store:         store,
			ArtifactTTL:   time.Hour,
			MaxObjectSize: 1024,
			TempDirectory: t.TempDir(),
		},
	).routesHandler()

	for requestNumber := 0; requestNumber < 2; requestNumber++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
		server.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Body.String() != "cached-artifact" {
			t.Fatalf("request %d status = %d body = %q", requestNumber, recorder.Code, recorder.Body.String())
		}
		if got := recorder.Header().Get("X-Package-Firewall-Cache"); got != "HIT" {
			t.Fatalf("request %d cache header = %q", requestNumber, got)
		}
	}
	if provider.calls != 2 {
		t.Fatalf("intel queries = %d want 2", provider.calls)
	}
	if store.getCalls != 2 {
		t.Fatalf("cache gets = %d want 2", store.getCalls)
	}
	if upstreamHits != 0 {
		t.Fatalf("upstream hits = %d want 0", upstreamHits)
	}

	metricsRecorder := httptest.NewRecorder()
	server.ServeHTTP(metricsRecorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsRecorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", metricsRecorder.Code)
	}
	if !strings.Contains(metricsRecorder.Body.String(), `package_firewall_cache_hits_total{route="npm"} 2`) {
		t.Fatalf("metrics did not expose cache hits:\n%s", metricsRecorder.Body.String())
	}
}

func TestBlockingPolicyRunsBeforeCacheLookup(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	engine, err := policy.New(policy.Config{Deny: []string{"pkg:npm/pkg@1.0.0"}})
	if err != nil {
		t.Fatal(err)
	}
	provider := &countingIntelProvider{}
	store := &repeatingHitStore{body: []byte("cached-artifact")}
	server := New(
		testCacheServerConfig(upstream.URL),
		engine,
		provider,
		proxy.CacheConfig{
			Store:         store,
			ArtifactTTL:   time.Hour,
			MaxObjectSize: 1024,
			TempDirectory: t.TempDir(),
		},
	).routesHandler()
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
	}
	if store.getCalls != 0 || provider.calls != 0 || upstreamHits != 0 {
		t.Fatalf("blocked request reached cache/intel/upstream: gets = %d intel = %d upstream = %d", store.getCalls, provider.calls, upstreamHits)
	}
}

func testCacheServerConfig(upstreamURL string) config.Config {
	cfg := config.Default()
	cfg.Server.PublicBaseURL = "http://firewall.test"
	cfg.Routes = []config.RouteConfig{{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: strings.TrimRight(upstreamURL, "/") + "/",
	}}
	return cfg
}

type countingIntelProvider struct {
	calls int
}

func (p *countingIntelProvider) Query(context.Context, policy.Package) (intel.Result, error) {
	p.calls++
	return intel.Result{}, nil
}

type repeatingHitStore struct {
	body     []byte
	getCalls int
}

func (s *repeatingHitStore) Get(context.Context, string) (artifactcache.Entry, error) {
	s.getCalls++
	digest := sha256.Sum256(s.body)
	return artifactcache.Entry{
		Headers:   http.Header{"Content-Type": []string{"application/octet-stream"}},
		Body:      io.NopCloser(bytes.NewReader(s.body)),
		SHA256:    hex.EncodeToString(digest[:]),
		Size:      int64(len(s.body)),
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func (*repeatingHitStore) Put(context.Context, string, artifactcache.PutRequest) error {
	return nil
}
