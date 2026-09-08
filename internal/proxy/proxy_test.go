package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/objectcache"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

func TestProxyRewritesPyPIFileURLs(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<a href="https://files.pythonhosted.org/packages/Django-5.0.6-py3-none-any.whl">wheel</a>`))
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{
		Name:        "pypi",
		Ecosystem:   "pypi",
		PathPrefix:  "/pypi/",
		UpstreamURL: upstream.URL + "/",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/pypi/simple/django/", nil)
	_, err := p.Serve(rec, req, route, registry.RequestInfo{UpstreamPath: "/simple/django/"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), `http://firewall.test/pypi/files/packages/Django-5.0.6-py3-none-any.whl`) {
		t.Fatalf("body was not rewritten: %s", rec.Body.String())
	}
}

func TestUpstreamURLRejectsUnsafePathSegments(t *testing.T) {
	route := config.RouteConfig{UpstreamURL: "https://registry.example/repository/npm/"}
	for _, upstreamPath := range []string{
		"/../admin",
		"/../../admin",
		"/%2e%2e/admin",
		"/%2E%2E/admin",
		"/safe/%2f/admin",
	} {
		t.Run(upstreamPath, func(t *testing.T) {
			if _, err := upstreamURL(route, registry.RequestInfo{UpstreamPath: upstreamPath}); err == nil {
				t.Fatal("expected unsafe upstream path to be rejected")
			}
		})
	}
}

func TestUpstreamURLPreservesSafeRouteBasePath(t *testing.T) {
	got, err := upstreamURL(
		config.RouteConfig{UpstreamURL: "https://registry.example/repository/npm/"},
		registry.RequestInfo{UpstreamPath: "/pkg/-/pkg-1.0.0.tgz"},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://registry.example/repository/npm/pkg/-/pkg-1.0.0.tgz"
	if got != want {
		t.Fatalf("upstream URL = %q want %q", got, want)
	}
}

func TestProxyStripsSensitiveRequestHeaders(t *testing.T) {
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: upstream.URL + "/",
	}
	req := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	req.Header.Set("Authorization", "Bearer client")
	req.Header.Set("Cookie", "session=secret")
	req.Header.Set("Cf-Access-Jwt-Assertion", "jwt")
	req.Header.Set("X-Amzn-Oidc-Data", "oidc")
	req.Header.Set("X-Forwarded-Access-Token", "token")
	req.Header.Set("Accept", "application/octet-stream")
	_, err := p.Serve(httptest.NewRecorder(), req, route, registry.RequestInfo{UpstreamPath: "/pkg/-/pkg-1.0.0.tgz"})
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"Authorization", "Cookie", "Cf-Access-Jwt-Assertion", "X-Amzn-Oidc-Data", "X-Forwarded-Access-Token"} {
		if got := seen.Get(header); got != "" {
			t.Fatalf("%s reached upstream as %q", header, got)
		}
	}
	if got := seen.Get("Accept"); got != "application/octet-stream" {
		t.Fatalf("Accept = %q", got)
	}
}

func TestProxyUsesConfiguredUpstreamTokenAfterStrippingClientAuth(t *testing.T) {
	t.Setenv("PFW_TEST_UPSTREAM_TOKEN", "upstream-secret")
	var auth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{
		Ecosystem:        "npm",
		PathPrefix:       "/npm/",
		UpstreamURL:      upstream.URL + "/",
		UpstreamTokenEnv: "PFW_TEST_UPSTREAM_TOKEN",
	}
	req := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	req.Header.Set("Authorization", "Bearer client")
	_, err := p.Serve(httptest.NewRecorder(), req, route, registry.RequestInfo{UpstreamPath: "/pkg/-/pkg-1.0.0.tgz"})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer upstream-secret" {
		t.Fatalf("Authorization = %q", auth)
	}
}

func TestProxyCachesArtifactResponses(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("artifact-body"))
	}))
	defer upstream.Close()
	store := newMemoryStore()
	p := New("http://firewall.test", CacheConfig{
		Store:                store,
		ArtifactTTL:          time.Hour,
		ArtifactStaleIfError: 24 * time.Hour,
		MaxObjectSize:        1024,
	})
	route := config.RouteConfig{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: upstream.URL + "/",
	}
	info := registry.RequestInfo{
		Kind:          "artifact",
		NeedsDecision: true,
		UpstreamPath:  "/lodash/-/lodash-4.17.21.tgz",
	}
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/npm/lodash/-/lodash-4.17.21.tgz", nil)
		_, err := p.Serve(rec, req, route, info)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Body.String() != "artifact-body" {
			t.Fatalf("body = %q", rec.Body.String())
		}
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits = %d", upstreamHits)
	}
}

func TestProxyServesStaleArtifactOnUpstreamError(t *testing.T) {
	store := newMemoryStore()
	key := objectcache.Key(http.MethodGet, "npm", "npm", "http://127.0.0.1:1/lodash/-/lodash-4.17.21.tgz")
	store.entries[key] = objectcache.Entry{
		Key:               key,
		StatusCode:        http.StatusOK,
		Headers:           http.Header{"Content-Type": []string{"application/octet-stream"}},
		Body:              io.NopCloser(strings.NewReader("cached-body")),
		ExpiresAt:         time.Now().Add(-time.Hour),
		StaleIfErrorUntil: time.Now().Add(time.Hour),
	}
	p := New("http://firewall.test", CacheConfig{
		Store:                store,
		ArtifactTTL:          time.Hour,
		ArtifactStaleIfError: 24 * time.Hour,
		MaxObjectSize:        1024,
	})
	route := config.RouteConfig{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: "http://127.0.0.1:1/",
	}
	info := registry.RequestInfo{
		Kind:          "artifact",
		NeedsDecision: true,
		UpstreamPath:  "/lodash/-/lodash-4.17.21.tgz",
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/npm/lodash/-/lodash-4.17.21.tgz", nil)
	_, err := p.Serve(rec, req, route, info)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Header().Get("X-Package-Firewall-Cache") != "STALE" {
		t.Fatalf("cache status = %q", rec.Header().Get("X-Package-Firewall-Cache"))
	}
	if rec.Body.String() != "cached-body" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

type memoryStore struct {
	entries map[string]objectcache.Entry
}

func newMemoryStore() *memoryStore {
	return &memoryStore{entries: map[string]objectcache.Entry{}}
}

func (s *memoryStore) Get(_ context.Context, key string) (objectcache.Entry, bool, error) {
	entry, ok := s.entries[key]
	if !ok {
		return objectcache.Entry{}, false, nil
	}
	body, err := io.ReadAll(entry.Body)
	if err != nil {
		return objectcache.Entry{}, false, err
	}
	entry.Body = io.NopCloser(bytes.NewReader(body))
	s.entries[key] = objectcache.Entry{
		Key:               entry.Key,
		StatusCode:        entry.StatusCode,
		Headers:           entry.Headers,
		Body:              io.NopCloser(bytes.NewReader(body)),
		SHA256:            entry.SHA256,
		Size:              entry.Size,
		FetchedAt:         entry.FetchedAt,
		ExpiresAt:         entry.ExpiresAt,
		StaleIfErrorUntil: entry.StaleIfErrorUntil,
		Immutable:         entry.Immutable,
	}
	return entry, true, nil
}

func (s *memoryStore) Put(_ context.Context, req objectcache.PutRequest) error {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	now := time.Now()
	s.entries[req.Key] = objectcache.Entry{
		Key:               req.Key,
		StatusCode:        req.StatusCode,
		Headers:           objectcache.SafeHeaders(req.Headers),
		Body:              io.NopCloser(bytes.NewReader(body)),
		SHA256:            req.ComputedSHA256,
		Size:              int64(len(body)),
		FetchedAt:         now,
		ExpiresAt:         now.Add(req.TTL),
		StaleIfErrorUntil: now.Add(req.TTL + req.StaleIfError),
		Immutable:         req.Immutable,
	}
	return nil
}
