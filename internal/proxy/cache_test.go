package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/artifactcache"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

func TestProxyCachesIntegrityCheckedArtifact(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", `"artifact-v1"`)
		_, _ = io.WriteString(w, "artifact-body")
	}))
	defer upstream.Close()

	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	route := testNPMRoute(upstream.URL)
	for requestNumber, wantCacheStatus := range []string{"MISS", "HIT"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
		result, err := proxy.Serve(recorder, request, route, exactArtifactInfo())
		if err != nil {
			t.Fatal(err)
		}
		if result.StatusCode != http.StatusOK || recorder.Code != http.StatusOK {
			t.Fatalf("request %d status = %d result = %d", requestNumber, recorder.Code, result.StatusCode)
		}
		if got := recorder.Body.String(); got != "artifact-body" {
			t.Fatalf("request %d body = %q", requestNumber, got)
		}
		if got := recorder.Header().Get(cacheHeader); got != wantCacheStatus {
			t.Fatalf("request %d cache header = %q want %q", requestNumber, got, wantCacheStatus)
		}
		if got := recorder.Header().Get("ETag"); got != `"artifact-v1"` {
			t.Fatalf("request %d ETag = %q", requestNumber, got)
		}
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits = %d want 1", upstreamHits)
	}
	if store.getCalls != 2 || store.putCalls != 1 {
		t.Fatalf("store calls: get = %d put = %d", store.getCalls, store.putCalls)
	}
	if metrics.hits["npm"] != 1 || metrics.misses["npm"] != 1 {
		t.Fatalf("metrics: hits = %v misses = %v", metrics.hits, metrics.misses)
	}
}

func TestProxyBypassesNonCanonicalRequests(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		method string
		path   string
		info   registry.RequestInfo
		mutate func(*http.Request)
	}{
		{name: "method", reason: "method", method: http.MethodHead, info: exactArtifactInfo()},
		{name: "metadata", reason: "not_exact_artifact", method: http.MethodGet, info: registry.RequestInfo{Kind: "metadata", UpstreamPath: "/pkg"}},
		{name: "query", reason: "query", method: http.MethodGet, path: "/npm/pkg/-/pkg-1.0.0.tgz?download=1", info: exactArtifactInfo()},
		{name: "range", reason: "range", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Range", "bytes=0-3")},
		{name: "conditional", reason: "conditional", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("If-None-Match", `"artifact-v1"`)},
		{name: "cache control", reason: "request_cache_control", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Cache-Control", "no-cache")},
		{name: "accept", reason: "representation", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Accept", "application/octet-stream")},
		{name: "encoding", reason: "representation", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Accept-Encoding", "gzip")},
		{name: "language", reason: "representation", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Accept-Language", "en-CA")},
		{name: "cookie", reason: "representation", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Cookie", "session=value")},
		{name: "body", reason: "request_body", method: http.MethodGet, info: exactArtifactInfo(), mutate: func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("body"))
			request.ContentLength = 4
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstreamHits := 0
			var upstreamQuery string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				upstreamHits++
				upstreamQuery = request.URL.RawQuery
				if request.Header.Get("Range") != "" {
					w.Header().Set("Content-Range", "bytes 0-3/8")
					w.WriteHeader(http.StatusPartialContent)
					_, _ = io.WriteString(w, "part")
					return
				}
				_, _ = io.WriteString(w, "upstream")
			}))
			defer upstream.Close()
			store := newMemoryArtifactStore()
			store.entries["unused"] = storedArtifact{body: []byte("cached")}
			metrics := newTestCacheMetrics()
			proxy := newTestCachingProxy(t, store, metrics, 1024)
			path := test.path
			if path == "" {
				path = "/npm/pkg/-/pkg-1.0.0.tgz"
			}
			request := httptest.NewRequest(test.method, path, nil)
			if test.mutate != nil {
				test.mutate(request)
			}
			recorder := httptest.NewRecorder()
			if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), test.info); err != nil {
				t.Fatal(err)
			}
			if store.getCalls != 0 || store.putCalls != 0 {
				t.Fatalf("cache was used: get = %d put = %d", store.getCalls, store.putCalls)
			}
			if upstreamHits != 1 {
				t.Fatalf("upstream hits = %d", upstreamHits)
			}
			if test.reason == "query" && upstreamQuery != "download=1" {
				t.Fatalf("upstream query = %q", upstreamQuery)
			}
			if test.reason == "range" && (recorder.Code != http.StatusPartialContent || recorder.Body.String() != "part") {
				t.Fatalf("range response status = %d body = %q", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get(cacheHeader); got != "BYPASS" {
				t.Fatalf("cache header = %q", got)
			}
			if got := metrics.bypasses[bypassMetricKey{route: "npm", reason: test.reason}]; got != 1 {
				t.Fatalf("bypass metric %q = %d", test.reason, got)
			}
		})
	}
}

func TestProxyStoresOnlyUnconditional200Responses(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		status int
		header http.Header
		body   string
		limit  int64
	}{
		{name: "partial status", reason: "upstream_status", status: http.StatusPartialContent, header: http.Header{"Content-Range": []string{"bytes 0-3/8"}}, body: "part", limit: 1024},
		{name: "not found", reason: "upstream_status", status: http.StatusNotFound, body: "missing", limit: 1024},
		{name: "vary", reason: "response_vary", status: http.StatusOK, header: http.Header{"Vary": []string{"Accept"}}, body: "artifact", limit: 1024},
		{name: "cookie", reason: "response_set_cookie", status: http.StatusOK, header: http.Header{"Set-Cookie": []string{"session=value"}}, body: "artifact", limit: 1024},
		{name: "content range", reason: "response_content_range", status: http.StatusOK, header: http.Header{"Content-Range": []string{"bytes 0-7/8"}}, body: "artifact", limit: 1024},
		{name: "encoding", reason: "response_encoding", status: http.StatusOK, header: http.Header{"Content-Encoding": []string{"gzip"}}, body: "artifact", limit: 1024},
		{name: "cache control", reason: "response_cache_control", status: http.StatusOK, header: http.Header{"Cache-Control": []string{"private, max-age=60"}}, body: "artifact", limit: 1024},
		{name: "known oversized", reason: "object_too_large", status: http.StatusOK, header: http.Header{"Content-Length": []string{"8"}}, body: "artifact", limit: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for key, values := range test.header {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer upstream.Close()
			store := newMemoryArtifactStore()
			metrics := newTestCacheMetrics()
			proxy := newTestCachingProxy(t, store, metrics, test.limit)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
			if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
				t.Fatal(err)
			}
			if store.getCalls != 1 || store.putCalls != 0 {
				t.Fatalf("store calls: get = %d put = %d", store.getCalls, store.putCalls)
			}
			if recorder.Body.String() != test.body {
				t.Fatalf("body = %q", recorder.Body.String())
			}
			if got := metrics.bypasses[bypassMetricKey{route: "npm", reason: test.reason}]; got != 1 {
				t.Fatalf("bypass metric %q = %d", test.reason, got)
			}
		})
	}
}

func TestProxyDoesNotCacheRedirectedArtifact(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "redirected-artifact")
	}))
	defer final.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, final.URL+"/artifact", http.StatusFound)
	}))
	defer upstream.Close()
	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "redirected-artifact" {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
	}
	if store.putCalls != 0 {
		t.Fatalf("cache put calls = %d", store.putCalls)
	}
	if got := metrics.bypasses[bypassMetricKey{route: "npm", reason: "upstream_redirect"}]; got != 1 {
		t.Fatalf("redirect bypasses = %d", got)
	}
}

func TestProxyDoesNotCacheRewrittenArtifactResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"dist":{"tarball":"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"}}`)
	}))
	defer upstream.Close()
	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	if store.putCalls != 0 {
		t.Fatalf("cache put calls = %d", store.putCalls)
	}
	if got := metrics.bypasses[bypassMetricKey{route: "npm", reason: "response_rewrite"}]; got != 1 {
		t.Fatalf("rewrite bypasses = %d", got)
	}
}

func TestProxyTreatsCacheReadFailuresAsCleanMisses(t *testing.T) {
	cachedBody := "cached-prefix"
	tests := []struct {
		name string
		get  func(context.Context, string) (artifactcache.Entry, error)
	}{
		{name: "lookup error", get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{}, errors.New("cache unavailable")
		}},
		{name: "body read error", get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{
				Body:      &readErrorAfterData{body: []byte(cachedBody)},
				SHA256:    checksum(cachedBody),
				Size:      int64(len(cachedBody)),
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}},
		{name: "truncated body", get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{
				Body:      io.NopCloser(strings.NewReader("short")),
				SHA256:    checksum(cachedBody),
				Size:      int64(len(cachedBody)),
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}},
		{name: "checksum mismatch", get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{
				Body:      io.NopCloser(strings.NewReader(cachedBody)),
				SHA256:    checksum("different"),
				Size:      int64(len(cachedBody)),
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upstreamHits := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits++
				_, _ = io.WriteString(w, "complete-upstream-body")
			}))
			defer upstream.Close()
			store := &stubArtifactStore{get: test.get, put: func(_ context.Context, _ string, req artifactcache.PutRequest) error {
				_, _ = io.Copy(io.Discard, req.Body)
				return nil
			}}
			metrics := newTestCacheMetrics()
			proxy := newTestCachingProxy(t, store, metrics, 1024)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
			if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
				t.Fatal(err)
			}
			if got := recorder.Body.String(); got != "complete-upstream-body" {
				t.Fatalf("body contains cached bytes or is incomplete: %q", got)
			}
			if got := recorder.Header().Get(cacheHeader); got != "MISS" {
				t.Fatalf("cache header = %q", got)
			}
			if upstreamHits != 1 || store.getCalls != 1 {
				t.Fatalf("upstream hits = %d cache gets = %d", upstreamHits, store.getCalls)
			}
			if metrics.readErrors["npm"] != 1 || metrics.misses["npm"] != 1 || metrics.hits["npm"] != 0 {
				t.Fatalf("metrics: read errors = %v misses = %v hits = %v", metrics.readErrors, metrics.misses, metrics.hits)
			}
		})
	}
}

func TestProxyTreatsStoreFailureAsSuccessfulMiss(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "complete-upstream-body")
	}))
	defer upstream.Close()
	store := &stubArtifactStore{
		get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{}, artifactcache.ErrNotFound
		},
		put: func(context.Context, string, artifactcache.PutRequest) error {
			return errors.New("S3 unavailable")
		},
	}
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Body.String(); got != "complete-upstream-body" {
		t.Fatalf("body = %q", got)
	}
	if metrics.misses["npm"] != 1 || metrics.storeErrors["npm"] != 1 {
		t.Fatalf("metrics: misses = %v store errors = %v", metrics.misses, metrics.storeErrors)
	}
}

func TestProxyTempStorageFailureFallsBackWithoutPartialResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "complete-upstream-body")
	}))
	defer upstream.Close()
	cachedBody := "cached-body"
	store := &stubArtifactStore{
		get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{
				Body:      io.NopCloser(strings.NewReader(cachedBody)),
				SHA256:    checksum(cachedBody),
				Size:      int64(len(cachedBody)),
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		put: func(context.Context, string, artifactcache.PutRequest) error {
			return nil
		},
	}
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	proxy.createTemp = func(string, string) (*os.File, error) {
		return nil, errors.New("temporary storage unavailable")
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Body.String(); got != "complete-upstream-body" {
		t.Fatalf("body contains cached bytes or is incomplete: %q", got)
	}
	if metrics.readErrors["npm"] != 1 || metrics.misses["npm"] != 1 || metrics.storeErrors["npm"] != 1 {
		t.Fatalf("metrics: read errors = %v misses = %v store errors = %v", metrics.readErrors, metrics.misses, metrics.storeErrors)
	}
}

func TestProxyBoundsUnknownLengthSpoolWhileStreaming(t *testing.T) {
	upstreamBody := "body-larger-than-limit"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, upstreamBody)
	}))
	defer upstream.Close()
	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 4)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	if recorder.Body.String() != upstreamBody {
		t.Fatalf("body = %q", recorder.Body.String())
	}
	if store.putCalls != 0 {
		t.Fatalf("cache put calls = %d", store.putCalls)
	}
	if got := metrics.bypasses[bypassMetricKey{route: "npm", reason: "object_too_large"}]; got != 1 {
		t.Fatalf("oversized bypasses = %d", got)
	}
}

func TestCaptureSpoolNeverWritesPastLimit(t *testing.T) {
	var client bytes.Buffer
	var temporary bytes.Buffer
	spool := newCaptureSpool(&temporary, 4)
	if err := streamAndCapture(&client, strings.NewReader("0123456789"), spool); err != nil {
		t.Fatal(err)
	}
	if client.String() != "0123456789" {
		t.Fatalf("client body = %q", client.String())
	}
	if temporary.String() != "0123" || temporary.Len() != 4 {
		t.Fatalf("temporary body = %q size = %d", temporary.String(), temporary.Len())
	}
	if !spool.overflow || spool.err != nil {
		t.Fatalf("overflow = %v error = %v", spool.overflow, spool.err)
	}
}

func TestCaptureSpoolWriteErrorDoesNotInterruptClient(t *testing.T) {
	var client bytes.Buffer
	spool := newCaptureSpool(errorWriter{}, 1024)
	if err := streamAndCapture(&client, strings.NewReader("complete-body"), spool); err != nil {
		t.Fatal(err)
	}
	if client.String() != "complete-body" {
		t.Fatalf("client body = %q", client.String())
	}
	if spool.err == nil {
		t.Fatal("expected isolated spool error")
	}
}

func newTestCachingProxy(t *testing.T, store artifactcache.Store, metrics CacheMetrics, limit int64) *Proxy {
	t.Helper()
	return New(
		"http://firewall.test",
		WithCache(CacheConfig{
			Store:         store,
			ArtifactTTL:   time.Hour,
			MaxObjectSize: limit,
			TempDirectory: t.TempDir(),
			Metrics:       metrics,
		}),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
}

func testNPMRoute(upstreamURL string) config.RouteConfig {
	return config.RouteConfig{
		Name:        "npm",
		Ecosystem:   "npm",
		PathPrefix:  "/npm/",
		UpstreamURL: strings.TrimRight(upstreamURL, "/") + "/",
	}
}

func exactArtifactInfo() registry.RequestInfo {
	return registry.RequestInfo{
		Kind:          "artifact",
		NeedsDecision: true,
		UpstreamPath:  "/pkg/-/pkg-1.0.0.tgz",
		Package: policy.Package{
			Ecosystem: "npm",
			Name:      "pkg",
			Version:   "1.0.0",
			PURL:      "pkg:npm/pkg@1.0.0",
		},
	}
}

func setHeader(name, value string) func(*http.Request) {
	return func(request *http.Request) {
		request.Header.Set(name, value)
	}
}

func checksum(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

type storedArtifact struct {
	headers   http.Header
	body      []byte
	sha256    string
	expiresAt time.Time
}

type memoryArtifactStore struct {
	entries  map[string]storedArtifact
	getCalls int
	putCalls int
}

func newMemoryArtifactStore() *memoryArtifactStore {
	return &memoryArtifactStore{entries: make(map[string]storedArtifact)}
}

func (s *memoryArtifactStore) Get(_ context.Context, key string) (artifactcache.Entry, error) {
	s.getCalls++
	entry, ok := s.entries[key]
	if !ok {
		return artifactcache.Entry{}, artifactcache.ErrNotFound
	}
	return artifactcache.Entry{
		Headers:   entry.headers.Clone(),
		Body:      io.NopCloser(bytes.NewReader(entry.body)),
		SHA256:    entry.sha256,
		Size:      int64(len(entry.body)),
		ExpiresAt: entry.expiresAt,
	}, nil
}

func (s *memoryArtifactStore) Put(_ context.Context, key string, req artifactcache.PutRequest) error {
	s.putCalls++
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	s.entries[key] = storedArtifact{
		headers:   artifactcache.SafeHeaders(req.Headers),
		body:      body,
		sha256:    req.SHA256,
		expiresAt: req.ExpiresAt,
	}
	return nil
}

type stubArtifactStore struct {
	get      func(context.Context, string) (artifactcache.Entry, error)
	put      func(context.Context, string, artifactcache.PutRequest) error
	getCalls int
	putCalls int
}

func (s *stubArtifactStore) Get(ctx context.Context, key string) (artifactcache.Entry, error) {
	s.getCalls++
	return s.get(ctx, key)
}

func (s *stubArtifactStore) Put(ctx context.Context, key string, req artifactcache.PutRequest) error {
	s.putCalls++
	return s.put(ctx, key, req)
}

type readErrorAfterData struct {
	body []byte
	done bool
}

func (r *readErrorAfterData) Read(destination []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(destination, r.body), nil
	}
	return 0, errors.New("cache body read failed")
}

func (*readErrorAfterData) Close() error { return nil }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("temporary storage failed")
}

type bypassMetricKey struct {
	route  string
	reason string
}

type testCacheMetrics struct {
	hits        map[string]int
	misses      map[string]int
	storeErrors map[string]int
	readErrors  map[string]int
	bypasses    map[bypassMetricKey]int
}

func newTestCacheMetrics() *testCacheMetrics {
	return &testCacheMetrics{
		hits:        make(map[string]int),
		misses:      make(map[string]int),
		storeErrors: make(map[string]int),
		readErrors:  make(map[string]int),
		bypasses:    make(map[bypassMetricKey]int),
	}
}

func (m *testCacheMetrics) Hit(route string)        { m.hits[route]++ }
func (m *testCacheMetrics) Miss(route string)       { m.misses[route]++ }
func (m *testCacheMetrics) StoreError(route string) { m.storeErrors[route]++ }
func (m *testCacheMetrics) ReadError(route string)  { m.readErrors[route]++ }
func (m *testCacheMetrics) Bypass(route, reason string) {
	m.bypasses[bypassMetricKey{route: route, reason: reason}]++
}
