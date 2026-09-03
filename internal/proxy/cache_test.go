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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/artifactcache"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/coordination"
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

func TestProxyCoalescesConcurrentCacheMissesInProcess(t *testing.T) {
	const requests = 24
	var upstreamHits atomic.Int32
	upstreamStarted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if upstreamHits.Add(1) == 1 {
			close(upstreamStarted)
		}
		<-releaseUpstream
		_, _ = io.WriteString(w, "artifact-body")
	}))
	defer upstream.Close()

	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	route := testNPMRoute(upstream.URL)
	start := make(chan struct{})
	results := make(chan error, requests)
	for range requests {
		go func() {
			<-start
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
			_, err := proxy.Serve(recorder, request, route, exactArtifactInfo())
			if err == nil && (recorder.Code != http.StatusOK || recorder.Body.String() != "artifact-body") {
				err = errors.New("unexpected proxy response")
			}
			results <- err
		}()
	}
	close(start)
	select {
	case <-upstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	waitForMetric(t, time.Second, func() bool { return metrics.fillWaiterCount("process") == requests-1 })
	close(releaseUpstream)
	for range requests {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d want 1", got)
	}
	if got := metrics.fillLeaderCount(); got != 1 {
		t.Fatalf("fill leaders = %d want 1", got)
	}
}

func TestProxyCoalescesConcurrentCacheMissesAcrossReplicas(t *testing.T) {
	const requests = 24
	var upstreamHits atomic.Int32
	upstreamStarted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if upstreamHits.Add(1) == 1 {
			close(upstreamStarted)
		}
		<-releaseUpstream
		_, _ = io.WriteString(w, "artifact-body")
	}))
	defer upstream.Close()

	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	coordinator := newMemoryCoordinator()
	proxies := []*Proxy{
		newTestCachingProxy(t, store, metrics, 1024),
		newTestCachingProxy(t, store, metrics, 1024),
	}
	for _, proxy := range proxies {
		proxy.coordination = CoordinationConfig{
			Coordinator:   coordinator,
			LeaseDuration: time.Minute,
			PollInterval:  5 * time.Millisecond,
		}
	}
	route := testNPMRoute(upstream.URL)
	start := make(chan struct{})
	results := make(chan error, requests)
	for index := range requests {
		proxy := proxies[index%len(proxies)]
		go func() {
			<-start
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
			_, err := proxy.Serve(recorder, request, route, exactArtifactInfo())
			if err == nil && (recorder.Code != http.StatusOK || recorder.Body.String() != "artifact-body") {
				err = errors.New("unexpected proxy response")
			}
			results <- err
		}()
	}
	close(start)
	select {
	case <-upstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("upstream request did not start")
	}
	waitForMetric(t, time.Second, func() bool { return metrics.fillWaiterCount("cluster") >= 1 })
	close(releaseUpstream)
	for range requests {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d want 1", got)
	}
	if got := metrics.fillLeaderCount(); got != 1 {
		t.Fatalf("fill leaders = %d want 1", got)
	}
}

func TestProxyCancelsFillWhenCoordinationLeaseCannotRenew(t *testing.T) {
	upstreamCanceled := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
		close(upstreamCanceled)
	}))
	defer upstream.Close()

	store := newMemoryArtifactStore()
	lease := &failingRenewLease{}
	proxy := newTestCachingProxy(t, store, newTestCacheMetrics(), 1024)
	proxy.coordination = CoordinationConfig{
		Coordinator:   &fixedLeaseCoordinator{lease: lease},
		LeaseDuration: 30 * time.Millisecond,
		PollInterval:  5 * time.Millisecond,
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	_, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fill error = %v want context cancellation", err)
	}
	select {
	case <-upstreamCanceled:
	case <-time.After(time.Second):
		t.Fatal("upstream fill was not canceled after lease renewal failed")
	}
	if !lease.released.Load() {
		t.Fatal("coordination lease was not released")
	}
	if store.putCalls != 0 {
		t.Fatalf("cache stores = %d want 0", store.putCalls)
	}
}

func TestProxyPreservesFreshnessAgeOnCacheHits(t *testing.T) {
	storedAt := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	current := storedAt
	originDate := storedAt.Add(-30 * time.Second).Format(http.TimeFormat)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Age", "100")
		w.Header().Set("Cache-Control", "public, max-age=120")
		w.Header().Set("Date", originDate)
		_, _ = io.WriteString(w, "artifact-body")
	}))
	defer upstream.Close()

	store := newMemoryArtifactStore()
	proxy := newTestCachingProxy(t, store, newTestCacheMetrics(), 1024)
	proxy.now = func() time.Time { return current }
	route := testNPMRoute(upstream.URL)
	for _, wantStatus := range []string{"MISS", "HIT"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
		if _, err := proxy.Serve(recorder, request, route, exactArtifactInfo()); err != nil {
			t.Fatal(err)
		}
		if got := recorder.Header().Get(cacheHeader); got != wantStatus {
			t.Fatalf("cache status = %q want %q", got, wantStatus)
		}
		if wantStatus == "MISS" {
			current = storedAt.Add(45 * time.Second)
			continue
		}
		if got := recorder.Header().Get("Date"); got != originDate {
			t.Fatalf("cached Date = %q want %q", got, originDate)
		}
		if got := recorder.Header().Get("Age"); got != "145" {
			t.Fatalf("cached Age = %q want 145", got)
		}
	}
}

func TestWithRequestQueryPreservesConfiguredParameters(t *testing.T) {
	requestURL, err := url.Parse("http://firewall.test/artifact?download=1&scope=client")
	if err != nil {
		t.Fatal(err)
	}
	target, err := withRequestQuery("https://registry.test/artifact?api-version=1&scope=route", requestURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	values := parsed.Query()
	if values.Get("api-version") != "1" || values.Get("download") != "1" {
		t.Fatalf("merged query = %v", values)
	}
	if scopes := values["scope"]; len(scopes) != 2 || scopes[0] != "route" || scopes[1] != "client" {
		t.Fatalf("merged scope values = %v", scopes)
	}
}

func TestProxyTimesOutCacheReadsAndFallsBackToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "complete-upstream-body")
	}))
	defer upstream.Close()
	store := &stubArtifactStore{
		get: func(ctx context.Context, _ string) (artifactcache.Entry, error) {
			<-ctx.Done()
			return artifactcache.Entry{}, ctx.Err()
		},
		put: func(_ context.Context, _ string, req artifactcache.PutRequest) error {
			_, err := io.Copy(io.Discard, req.Body)
			return err
		},
	}
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	proxy.cache.ReadTimeout = 20 * time.Millisecond
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	started := time.Now()
	if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("cache timeout fallback took %s", elapsed)
	}
	if recorder.Body.String() != "complete-upstream-body" || recorder.Header().Get(cacheHeader) != "MISS" {
		t.Fatalf("response status = %d cache = %q body = %q", recorder.Code, recorder.Header().Get(cacheHeader), recorder.Body.String())
	}
	if metrics.readErrors["npm"] != 1 || metrics.misses["npm"] != 1 {
		t.Fatalf("metrics: read errors = %v misses = %v", metrics.readErrors, metrics.misses)
	}
}

func TestProxyCompletesChunkedResponseBeforeCacheStore(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "artifact-body")
	}))
	defer upstream.Close()
	store := &blockingPutStore{
		started:  make(chan struct{}),
		release:  make(chan struct{}),
		finished: make(chan struct{}),
	}
	released := false
	defer func() {
		if !released {
			close(store.release)
		}
	}()
	proxy := New(
		"http://firewall.test",
		WithCache(CacheConfig{
			Store:         store,
			ArtifactTTL:   time.Hour,
			MaxObjectSize: 1024,
			TempDirectory: t.TempDir(),
			ReadTimeout:   time.Second,
			StoreTimeout:  5 * time.Second,
		}),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = proxy.Serve(w, r, testNPMRoute(upstream.URL), exactArtifactInfo())
	}))
	defer downstream.Close()

	type responseResult struct {
		body []byte
		err  error
	}
	responseDone := make(chan responseResult, 1)
	go func() {
		client := &http.Client{Timeout: 2 * time.Second}
		request, err := http.NewRequest(http.MethodGet, downstream.URL+"/npm/pkg/-/pkg-1.0.0.tgz", nil)
		if err != nil {
			responseDone <- responseResult{err: err}
			return
		}
		request.Header.Set("Accept-Encoding", "identity")
		response, err := client.Do(request)
		if err != nil {
			responseDone <- responseResult{err: err}
			return
		}
		body, readErr := io.ReadAll(response.Body)
		responseDone <- responseResult{body: body, err: errors.Join(readErr, response.Body.Close())}
	}()
	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("cache store did not start")
	}
	select {
	case result := <-responseDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if string(result.body) != "artifact-body" {
			t.Fatalf("response body = %q", result.body)
		}
	case <-time.After(time.Second):
		t.Fatal("chunked response waited for cache store completion")
	}
	close(store.release)
	released = true
	select {
	case <-store.finished:
	case <-time.After(time.Second):
		t.Fatal("cache store did not finish")
	}
}

func TestProxySharesIdentityArtifactWhenResponseDoesNotVaryOnAccept(t *testing.T) {
	upstreamHits := 0
	var upstreamEncodings []string
	var upstreamAccepts []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		upstreamHits++
		upstreamEncodings = append(upstreamEncodings, request.Header.Get("Accept-Encoding"))
		upstreamAccepts = append(upstreamAccepts, request.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Vary", "Accept-Encoding")
		_, _ = io.WriteString(w, "artifact-body")
	}))
	defer upstream.Close()

	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	route := testNPMRoute(upstream.URL)
	tests := []struct {
		accept         string
		acceptEncoding string
	}{
		{accept: "application/octet-stream", acceptEncoding: "gzip"},
		{acceptEncoding: "br"},
		{accept: "*/*", acceptEncoding: "gzip, deflate"},
		{accept: "Application/Octet-Stream", acceptEncoding: "zstd"},
	}
	for requestNumber, test := range tests {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
		request.Header.Set("Accept", test.accept)
		request.Header.Set("Accept-Encoding", test.acceptEncoding)
		if _, err := proxy.Serve(recorder, request, route, exactArtifactInfo()); err != nil {
			t.Fatal(err)
		}
		wantStatus := "HIT"
		if requestNumber == 0 {
			wantStatus = "MISS"
		}
		if got := recorder.Header().Get(cacheHeader); got != wantStatus {
			t.Fatalf("request %d cache header = %q want %q", requestNumber, got, wantStatus)
		}
		if got := recorder.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("request %d content type = %q", requestNumber, got)
		}
		if got := recorder.Header().Get("Vary"); got != "Accept-Encoding" {
			t.Fatalf("request %d Vary = %q", requestNumber, got)
		}
		if got := recorder.Body.String(); got != "artifact-body" {
			t.Fatalf("request %d body = %q", requestNumber, got)
		}
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits = %d want 1", upstreamHits)
	}
	if got := strings.Join(upstreamEncodings, ","); got != "identity" {
		t.Fatalf("upstream Accept-Encoding values = %q", got)
	}
	if got := strings.Join(upstreamAccepts, ","); got != "application/octet-stream" {
		t.Fatalf("upstream Accept values = %q", got)
	}
	if store.getCalls != 4 || store.putCalls != 1 {
		t.Fatalf("store calls: get = %d put = %d", store.getCalls, store.putCalls)
	}
	if metrics.hits["npm"] != 3 || metrics.misses["npm"] != 1 {
		t.Fatalf("metrics: hits = %v misses = %v", metrics.hits, metrics.misses)
	}
}

func TestProxyDoesNotStoreResponsesVaryingOnAccept(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", request.Header.Get("Accept"))
		w.Header().Set("Vary", "Accept")
		_, _ = io.WriteString(w, request.Header.Get("Accept"))
	}))
	defer upstream.Close()

	store := newMemoryArtifactStore()
	metrics := newTestCacheMetrics()
	proxy := newTestCachingProxy(t, store, metrics, 1024)
	for requestNumber, accept := range []string{"application/xml", "application/octet-stream"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
		request.Header.Set("Accept", accept)
		if _, err := proxy.Serve(recorder, request, testNPMRoute(upstream.URL), exactArtifactInfo()); err != nil {
			t.Fatal(err)
		}
		if got := recorder.Header().Get(cacheHeader); got != "MISS" {
			t.Fatalf("request %d cache header = %q", requestNumber, got)
		}
		if got := recorder.Header().Get("Vary"); got != "Accept" {
			t.Fatalf("request %d Vary = %q", requestNumber, got)
		}
		if got := recorder.Body.String(); got != accept {
			t.Fatalf("request %d body = %q want %q", requestNumber, got, accept)
		}
	}
	if upstreamHits != 2 {
		t.Fatalf("upstream hits = %d want 2", upstreamHits)
	}
	if store.getCalls != 2 || store.putCalls != 0 {
		t.Fatalf("store calls: get = %d put = %d", store.getCalls, store.putCalls)
	}
	if metrics.misses["npm"] != 2 {
		t.Fatalf("misses = %v", metrics.misses)
	}
	if got := metrics.bypasses[bypassMetricKey{route: "npm", reason: "response_vary"}]; got != 2 {
		t.Fatalf("response_vary bypasses = %d", got)
	}
}

func TestIdentityEncodingAccepted(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "absent", want: true},
		{name: "common compression", values: []string{"gzip, br"}, want: true},
		{name: "identity allowed", values: []string{"gzip, identity;q=0.5, *;q=0"}, want: true},
		{name: "identity refused", values: []string{"gzip, identity;q=0"}},
		{name: "wildcard refused", values: []string{"gzip", "*;q=0"}},
		{name: "identity overrides wildcard", values: []string{"gzip, *;q=0, identity"}, want: true},
		{name: "identity refusal overrides wildcard", values: []string{"*;q=1, identity;q=0"}},
		{name: "invalid quality", values: []string{"identity;q=invalid"}},
		{name: "too many quality digits", values: []string{"identity;q=0.0001"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := identityEncodingAccepted(test.values); got != test.want {
				t.Fatalf("identityEncodingAccepted(%q) = %v want %v", test.values, got, test.want)
			}
		})
	}
}

func TestCacheableResponseVary(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "absent", want: true},
		{name: "accept", values: []string{"Accept"}},
		{name: "encoding", values: []string{"Accept-Encoding"}, want: true},
		{name: "combined", values: []string{"Accept", "accept-encoding"}},
		{name: "language", values: []string{"Accept-Language"}},
		{name: "wildcard", values: []string{"*"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			for _, value := range test.values {
				header.Add("Vary", value)
			}
			if got := cacheableResponseVary(header); got != test.want {
				t.Fatalf("cacheableResponseVary(%q) = %v want %v", test.values, got, test.want)
			}
		})
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
		{name: "identity encoding refused", reason: "representation", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Accept-Encoding", "gzip, identity;q=0")},
		{name: "wildcard encoding refused", reason: "representation", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Accept-Encoding", "gzip, *;q=0")},
		{name: "invalid encoding quality", reason: "representation", method: http.MethodGet, info: exactArtifactInfo(), mutate: setHeader("Accept-Encoding", "gzip, identity;q=invalid")},
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
		{name: "rate limited", reason: "upstream_status", status: http.StatusTooManyRequests, header: http.Header{"Retry-After": []string{"60"}}, body: "rate limited", limit: 1024},
		{name: "vary", reason: "response_vary", status: http.StatusOK, header: http.Header{"Vary": []string{"Accept-Language"}}, body: "artifact", limit: 1024},
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
	route := testNPMRoute(upstream.URL)
	route.AllowedRedirectOrigins = []string{final.URL}
	if _, err := proxy.Serve(recorder, request, route, exactArtifactInfo()); err != nil {
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
				StoredAt:  time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}},
		{name: "truncated body", get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{
				Body:      io.NopCloser(strings.NewReader("short")),
				SHA256:    checksum(cachedBody),
				Size:      int64(len(cachedBody)),
				StoredAt:  time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}},
		{name: "checksum mismatch", get: func(context.Context, string) (artifactcache.Entry, error) {
			return artifactcache.Entry{
				Body:      io.NopCloser(strings.NewReader(cachedBody)),
				SHA256:    checksum("different"),
				Size:      int64(len(cachedBody)),
				StoredAt:  time.Now(),
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
				StoredAt:  time.Now(),
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
	proxy := New(
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
	proxy.startStore = func(store func()) { store() }
	return proxy
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
	storedAt  time.Time
	expiresAt time.Time
}

type memoryArtifactStore struct {
	mu       sync.Mutex
	entries  map[string]storedArtifact
	getCalls int
	putCalls int
}

func newMemoryArtifactStore() *memoryArtifactStore {
	return &memoryArtifactStore{entries: make(map[string]storedArtifact)}
}

func (s *memoryArtifactStore) Get(_ context.Context, key string) (artifactcache.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		StoredAt:  entry.storedAt,
		ExpiresAt: entry.expiresAt,
	}, nil
}

func (s *memoryArtifactStore) Put(_ context.Context, key string, req artifactcache.PutRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.putCalls++
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	s.entries[key] = storedArtifact{
		headers:   artifactcache.SafeHeaders(req.Headers),
		body:      body,
		sha256:    req.SHA256,
		storedAt:  req.StoredAt,
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

type blockingPutStore struct {
	started  chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (*blockingPutStore) Get(context.Context, string) (artifactcache.Entry, error) {
	return artifactcache.Entry{}, artifactcache.ErrNotFound
}

func (s *blockingPutStore) Put(ctx context.Context, _ string, req artifactcache.PutRequest) error {
	defer close(s.finished)
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		return err
	}
	close(s.started)
	select {
	case <-s.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
	mu          sync.Mutex
	hits        map[string]int
	misses      map[string]int
	storeErrors map[string]int
	readErrors  map[string]int
	bypasses    map[bypassMetricKey]int
	fillLeaders map[string]int
	fillWaiters map[fillWaiterMetricKey]int
}

func newTestCacheMetrics() *testCacheMetrics {
	return &testCacheMetrics{
		hits:        make(map[string]int),
		misses:      make(map[string]int),
		storeErrors: make(map[string]int),
		readErrors:  make(map[string]int),
		bypasses:    make(map[bypassMetricKey]int),
		fillLeaders: make(map[string]int),
		fillWaiters: make(map[fillWaiterMetricKey]int),
	}
}

func (m *testCacheMetrics) Hit(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hits[route]++
}
func (m *testCacheMetrics) Miss(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.misses[route]++
}
func (m *testCacheMetrics) StoreError(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeErrors[route]++
}
func (m *testCacheMetrics) ReadError(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readErrors[route]++
}
func (m *testCacheMetrics) Bypass(route, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypasses[bypassMetricKey{route: route, reason: reason}]++
}

type fillWaiterMetricKey struct {
	route string
	scope string
}

func (m *testCacheMetrics) CacheFillLeader(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fillLeaders[route]++
}

func (m *testCacheMetrics) CacheFillWaiter(route, scope string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fillWaiters[fillWaiterMetricKey{route: route, scope: scope}]++
}

func (m *testCacheMetrics) fillLeaderCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fillLeaders["npm"]
}

func (m *testCacheMetrics) fillWaiterCount(scope string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fillWaiters[fillWaiterMetricKey{route: "npm", scope: scope}]
}

func waitForMetric(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ready() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for metric")
		}
		time.Sleep(time.Millisecond)
	}
}

type memoryCoordinator struct {
	mu        sync.Mutex
	resources map[string]string
	nextOwner int
	cooldowns map[string]time.Time
}

func newMemoryCoordinator() *memoryCoordinator {
	return &memoryCoordinator{resources: make(map[string]string), cooldowns: make(map[string]time.Time)}
}

func (c *memoryCoordinator) TryAcquire(_ context.Context, resource string, _ time.Duration) (coordination.Lease, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.resources[resource]; ok {
		return nil, false, nil
	}
	c.nextOwner++
	owner := strconv.Itoa(c.nextOwner)
	c.resources[resource] = owner
	return &memoryLease{coordinator: c, resource: resource, owner: owner}, true, nil
}

func (c *memoryCoordinator) Cooldown(_ context.Context, route string) (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cooldowns[route], nil
}

func (c *memoryCoordinator) SetCooldown(_ context.Context, route string, until time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if until.After(c.cooldowns[route]) {
		c.cooldowns[route] = until
	}
	return nil
}

type memoryLease struct {
	coordinator *memoryCoordinator
	resource    string
	owner       string
}

func (*memoryLease) Renew(context.Context, time.Duration) error { return nil }

func (l *memoryLease) Release(context.Context) error {
	l.coordinator.mu.Lock()
	defer l.coordinator.mu.Unlock()
	if l.coordinator.resources[l.resource] != l.owner {
		return coordination.ErrLeaseLost
	}
	delete(l.coordinator.resources, l.resource)
	return nil
}

type fixedLeaseCoordinator struct {
	lease coordination.Lease
}

func (c *fixedLeaseCoordinator) TryAcquire(context.Context, string, time.Duration) (coordination.Lease, bool, error) {
	return c.lease, true, nil
}

func (*fixedLeaseCoordinator) Cooldown(context.Context, string) (time.Time, error) {
	return time.Time{}, nil
}

func (*fixedLeaseCoordinator) SetCooldown(context.Context, string, time.Time) error {
	return nil
}

type failingRenewLease struct {
	released atomic.Bool
}

func (*failingRenewLease) Renew(context.Context, time.Duration) error {
	return errors.New("coordination unavailable")
}

func (l *failingRenewLease) Release(context.Context) error {
	l.released.Store(true)
	return nil
}
