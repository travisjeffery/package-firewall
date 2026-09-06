package proxy

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/artifactcache"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

func TestNPMFreshnessLifetime(t *testing.T) {
	for _, test := range []struct {
		control string
		seconds int
	}{
		{"public, must-revalidate, max-age=31557600", 31557600},
		{"public, max-age=60", 60},
		{"public, immutable, max-age=60", 60},
		{"public, proxy-revalidate, max-age=60", 60},
		{"PUBLIC, MAX-AGE = 60, no-transform", 60},
		{"public, max-age=60, s-maxage=10", 10},
		{"public, max-age=0, s-maxage=60", 60},
		{"public, s-maxage=60", 60},
		{"public, max-age=0", 0},
		{"public, max-age=60, s-maxage=0", 0},
		{"public, immutable", 0},
		{"must-revalidate, max-age=60", 0},
		{"public=false, max-age=60", 0},
		{"public, must-revalidate=false, max-age=60", 0},
		{"public, max-age=60, private", 0},
		{"public, max-age=60, private = field", 0},
		{"public, max-age=60, no-store", 0},
		{"public, max-age=60, no-cache", 0},
		{"public, max-age=60, must-understand", 0},
		{"public, max-age=60, max-age=60", 0},
		{"public, max-age=60, s-maxage=10, s-maxage=20", 0},
		{"public, max-age=-1", 0},
		{"public, max-age=+60", 0},
		{"public, max-age=1.5", 0},
		{"public, max-age=invalid", 0},
		{"public, max-age=99999999999999999999999", 0},
		{"public, max-age=", 0},
		{`public, max-age="60"`, 0},
		{`foo="x, public, max-age=60, y"`, 0},
	} {
		t.Run(test.control, func(t *testing.T) {
			lifetime, ok := npmFreshnessLifetime(http.Header{"Cache-Control": {test.control}})
			if ok != (test.seconds > 0) || (ok && lifetime != time.Duration(test.seconds)*time.Second) {
				t.Fatalf("freshness = %s, %v; want %ds", lifetime, ok, test.seconds)
			}
		})
	}
	if _, ok := npmFreshnessLifetime(http.Header{"Cache-Control": {"public, max-age=60", "max-age=10"}}); ok {
		t.Fatal("duplicate freshness directives across header fields accepted")
	}
}

func TestProxyNPMRevalidationFreshnessAcrossReplicas(t *testing.T) {
	for _, control := range []string{
		"public, must-revalidate, max-age=60",
		"public, proxy-revalidate, max-age=60",
		"public, max-age=600, s-maxage=60",
		"public, max-age=0, s-maxage=60",
		"public, immutable, max-age=60",
	} {
		t.Run(control, func(t *testing.T) {
			path := "/npm/@adobe/css-tools/-/css-tools-4.4.0.tgz"
			info := registry.Identify(registry.Route{Ecosystem: "npm", PathPrefix: "/npm/"}, path)
			start := time.Date(2026, 9, 6, 4, 0, 0, 0, time.UTC)
			current := start
			store := newMemoryArtifactStore()
			metrics := newTestCacheMetrics()
			calls := 0
			transport := npmCookieTransport(func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/@adobe/css-tools/-/css-tools-4.4.0.tgz" {
					t.Fatalf("unexpected upstream path: %s", request.URL.Path)
				}
				calls++
				response := npmCookieResponse(request, []string{"__cf_bm=bot; Secure", "_cfuvid=visitor; Secure"})
				response.Header.Set("Cache-Control", control)
				response.Header.Set("Age", "20")
				response.Header.Set("Date", current.Add(-10*time.Second).Format(http.TimeFormat))
				current = current.Add(5 * time.Second)
				response.Body = &npmDelayedBody{Reader: strings.NewReader("artifact"), advance: func() { current = current.Add(5 * time.Second) }}
				return response, nil
			})
			for _, step := range []struct {
				elapsed time.Duration
				status  string
			}{
				{0, "MISS"},
				{39 * time.Second, "HIT"},
				{40 * time.Second, "MISS"},
			} {
				current = start.Add(step.elapsed)
				proxy := newTestCachingProxy(t, store, metrics, 1024)
				proxy.now = func() time.Time { return current }
				proxy.client = &http.Client{Transport: transport}
				recorder := httptest.NewRecorder()
				_, err := proxy.Serve(recorder, httptest.NewRequest(http.MethodGet, path, nil), testNPMRoute("https://registry.npmjs.org"), info)
				if err != nil {
					t.Fatal(err)
				}
				if recorder.Header().Get(cacheHeader) != step.status || recorder.Body.String() != "artifact" || recorder.Header().Get("Cache-Control") != control {
					t.Fatalf("unexpected response: %v %q", recorder.Header(), recorder.Body.String())
				}
				if len(recorder.Header().Values("Set-Cookie")) != 0 {
					t.Fatal("CDN cookie forwarded")
				}
				if step.status == "HIT" && recorder.Header().Get("Age") != "59" {
					t.Fatalf("hit Age = %q, want 59", recorder.Header().Get("Age"))
				}
				if step.elapsed == 0 {
					for _, entry := range store.entries {
						if !entry.expiresAt.Equal(start.Add(40*time.Second)) || entry.headers.Get("Age") != "30" || len(entry.headers.Values("Set-Cookie")) != 0 {
							t.Fatalf("stored expiry or headers incorrect: %s %v", entry.expiresAt, entry.headers)
						}
					}
				}
			}
			if calls != 2 || store.putCalls != 2 || metrics.hits["npm"] != 1 || len(metrics.bypasses) != 0 {
				t.Fatalf("calls=%d stores=%d metrics=%+v", calls, store.putCalls, metrics)
			}
		})
	}
}

func TestProxyNPMRejectsUnusableFreshness(t *testing.T) {
	for _, headers := range []http.Header{
		{"Cache-Control": {"public, max-age=60"}, "Age": {"60"}},
		{"Cache-Control": {"public, max-age=60"}, "Age": {"invalid"}},
		{"Cache-Control": {"public, max-age=60"}, "Age": {"1", "2"}},
		{"Cache-Control": {"public, max-age=60"}, "Date": {"invalid"}},
		{"Cache-Control": {"public, max-age=60"}, "Date": {"Sun, 06 Sep 2026 03:00:00 GMT"}},
		{"Cache-Control": {"public, max-age=60, max-age=120"}},
		{"Cache-Control": {"public, max-age=60", "max-age=120"}},
		{"Cache-Control": {"public, max-age=60, extension"}},
		{"Cache-Control": {"public, max-age=0, s-maxage=0"}},
		{"Cache-Control": {"public, max-age=60, s-maxage=0"}},
		{"Cache-Control": {"public, immutable"}},
		{},
		{"Cache-Control": {"public, max-age=60"}, "Pragma": {"extension, no-cache"}},
		{"Cache-Control": {"public, max-age=60"}, "Pragma": {"extension", "no-cache"}},
	} {
		for _, cookies := range [][]string{nil, {"__cf_bm=bot; Secure"}} {
			t.Run(fmt.Sprintf("%v/cookies=%v", headers, cookies != nil), func(t *testing.T) {
				store := newMemoryArtifactStore()
				metrics := newTestCacheMetrics()
				calls := 0
				for range 2 {
					proxy := newTestCachingProxy(t, store, metrics, 1024)
					proxy.now = func() time.Time { return time.Date(2026, 9, 6, 4, 0, 0, 0, time.UTC) }
					proxy.client = &http.Client{Transport: npmCookieTransport(func(request *http.Request) (*http.Response, error) {
						calls++
						response := npmCookieResponse(request, cookies)
						response.Header = headers.Clone()
						for _, cookie := range cookies {
							response.Header.Add("Set-Cookie", cookie)
						}
						return response, nil
					})}
					recorder := httptest.NewRecorder()
					_, err := proxy.Serve(recorder, httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil), testNPMRoute("https://registry.npmjs.org"), exactArtifactInfo())
					if err != nil || recorder.Code != http.StatusOK || recorder.Body.String() != "artifact" || recorder.Header().Get(cacheHeader) == "HIT" {
						t.Fatalf("invalid freshness response: err=%v status=%d cache=%q body=%q", err, recorder.Code, recorder.Header().Get(cacheHeader), recorder.Body.String())
					}
				}
				if calls != 2 || store.putCalls != 0 || len(store.entries) != 0 || metrics.bypasses[bypassMetricKey{"npm", "response_cache_control"}] != 2 {
					t.Fatalf("calls=%d stores=%d entries=%d bypasses=%v", calls, store.putCalls, len(store.entries), metrics.bypasses)
				}
			})
		}
	}
}

func TestProxyNPMDoesNotReuseLegacyFreshnessEntries(t *testing.T) {
	current := time.Now().UTC().Truncate(time.Second)
	route := testNPMRoute("https://registry.npmjs.org")
	target := "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
	legacyKey := artifactcache.Key(http.MethodGet, route.Name, route.Ecosystem, target)
	store := newMemoryArtifactStore()
	if err := store.Put(context.Background(), legacyKey, artifactcache.PutRequest{
		Headers: http.Header{"Cache-Control": {"public, immutable, max-age=60"}},
		Body:    strings.NewReader("legacy"), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("legacy"))), Size: 6,
		StoredAt: current.Add(-time.Hour), ExpiresAt: current.Add(23 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	metrics := newTestCacheMetrics()
	calls := 0
	for _, want := range []string{"MISS", "HIT"} {
		proxy := newTestCachingProxy(t, store, metrics, 1024)
		proxy.now = func() time.Time { return current }
		proxy.client = &http.Client{Transport: npmCookieTransport(func(request *http.Request) (*http.Response, error) {
			calls++
			return npmCookieResponse(request, nil), nil
		})}
		request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
		recorder := httptest.NewRecorder()
		_, err := proxy.Serve(recorder, request, route, exactArtifactInfo())
		if err != nil || recorder.Body.String() != "artifact" || recorder.Header().Get(cacheHeader) != want {
			t.Fatalf("legacy cache isolation: err=%v body=%q cache=%q", err, recorder.Body.String(), recorder.Header().Get(cacheHeader))
		}
		otherRoute := route
		otherRoute.Name, otherRoute.Ecosystem = "maven", "maven"
		key, reason := proxy.cacheKey(request, otherRoute, exactArtifactInfo(), target)
		if reason != "" || key != artifactcache.Key(http.MethodGet, otherRoute.Name, otherRoute.Ecosystem, target) {
			t.Fatal("non-npm cache key changed")
		}
	}
	if calls != 1 || len(store.entries) != 2 {
		t.Fatalf("calls=%d entries=%d", calls, len(store.entries))
	}
}

func TestProxyNPMFreshnessExpiresDuringDownload(t *testing.T) {
	current := time.Now()
	store := newMemoryArtifactStore()
	proxy := newTestCachingProxy(t, store, newTestCacheMetrics(), 1024)
	proxy.now = func() time.Time { return current }
	proxy.client = &http.Client{Transport: npmCookieTransport(func(request *http.Request) (*http.Response, error) {
		response := npmCookieResponse(request, []string{"__cf_bm=bot"})
		response.Header.Set("Cache-Control", "public, must-revalidate, max-age=1")
		response.Body = &npmDelayedBody{Reader: strings.NewReader("artifact"), advance: func() { current = current.Add(2 * time.Second) }}
		return response, nil
	})}
	recorder := httptest.NewRecorder()
	_, err := proxy.Serve(recorder, httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil), testNPMRoute("https://registry.npmjs.org"), exactArtifactInfo())
	if err != nil || recorder.Body.String() != "artifact" || store.putCalls != 0 {
		t.Fatalf("expired download: err=%v body=%q stores=%d", err, recorder.Body.String(), store.putCalls)
	}
}

func TestProxyNPMNeverServesStaleOnUpstreamFailure(t *testing.T) {
	current := time.Now()
	store := newMemoryArtifactStore()
	proxy := newTestCachingProxy(t, store, newTestCacheMetrics(), 1024)
	proxy.now = func() time.Time { return current }
	calls := 0
	upstreamError := errors.New("upstream unavailable")
	proxy.client = &http.Client{Transport: npmCookieTransport(func(request *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			return nil, upstreamError
		}
		response := npmCookieResponse(request, []string{"__cf_bm=bot"})
		response.Header.Set("Cache-Control", "public, must-revalidate, max-age=1")
		return response, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	route := testNPMRoute("https://registry.npmjs.org")
	if _, err := proxy.Serve(httptest.NewRecorder(), request, route, exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	current = current.Add(time.Second)
	recorder := httptest.NewRecorder()
	_, err := proxy.Serve(recorder, request, route, exactArtifactInfo())
	if !errors.Is(err, upstreamError) || recorder.Body.Len() != 0 || recorder.Header().Get(cacheHeader) == "HIT" {
		t.Fatalf("stale fallback: err=%v response=%v %q", err, recorder.Header(), recorder.Body.String())
	}
}

func TestProxyNPMFreshnessRespectsConfiguredTTL(t *testing.T) {
	current := time.Now()
	store := newMemoryArtifactStore()
	proxy := newTestCachingProxy(t, store, newTestCacheMetrics(), 1024)
	proxy.now = func() time.Time { return current }
	proxy.cache.ArtifactTTL = 10 * time.Second
	proxy.client = &http.Client{Transport: npmCookieTransport(func(request *http.Request) (*http.Response, error) {
		response := npmCookieResponse(request, nil)
		response.Header.Set("Cache-Control", "public, must-revalidate, max-age=60")
		return response, nil
	})}
	_, err := proxy.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil), testNPMRoute("https://registry.npmjs.org"), exactArtifactInfo())
	if err != nil || store.putCalls != 1 {
		t.Fatalf("err=%v stores=%d", err, store.putCalls)
	}
	for _, entry := range store.entries {
		if !entry.expiresAt.Equal(current.Add(10 * time.Second)) {
			t.Fatalf("expiry %s exceeds configured TTL", entry.expiresAt)
		}
	}
}

func TestProxyRejectsEntryExpiringDuringCacheRead(t *testing.T) {
	current := time.Now()
	store := newMemoryArtifactStore()
	proxy := newTestCachingProxy(t, store, newTestCacheMetrics(), 1024)
	proxy.now = func() time.Time { return current }
	calls := 0
	proxy.client = &http.Client{Transport: npmCookieTransport(func(request *http.Request) (*http.Response, error) {
		calls++
		response := npmCookieResponse(request, []string{"__cf_bm=bot"})
		response.Header.Set("Cache-Control", "public, must-revalidate, max-age=1")
		return response, nil
	})}
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
	route := testNPMRoute("https://registry.npmjs.org")
	if _, err := proxy.Serve(httptest.NewRecorder(), request, route, exactArtifactInfo()); err != nil {
		t.Fatal(err)
	}
	proxy.cache.Store = &stubArtifactStore{
		get: func(ctx context.Context, key string) (artifactcache.Entry, error) {
			entry, err := store.Get(ctx, key)
			entry.Body = &npmDelayedBody{Reader: entry.Body, advance: func() { current = current.Add(time.Second) }}
			return entry, err
		},
		put: store.Put,
	}
	recorder := httptest.NewRecorder()
	_, err := proxy.Serve(recorder, request, route, exactArtifactInfo())
	if err != nil || calls != 2 || recorder.Header().Get(cacheHeader) != "MISS" {
		t.Fatalf("expired cache read: err=%v calls=%d status=%q", err, calls, recorder.Header().Get(cacheHeader))
	}
}

func TestNPMFreshnessUsesApparentAge(t *testing.T) {
	current := time.Now().UTC().Truncate(time.Second)
	proxy := newTestCachingProxy(t, newMemoryArtifactStore(), newTestCacheMetrics(), 1024)
	request := httptest.NewRequest(http.MethodGet, "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", nil)
	response := npmCookieResponse(request, []string{"__cf_bm=bot"})
	response.Header.Set("Cache-Control", "public, must-revalidate, max-age=60")
	response.Header.Set("Age", "10")
	response.Header.Set("Date", current.Add(-50*time.Second).Format(http.TimeFormat))
	expiry, reason := proxy.prepareNPMCacheResponse(response, testNPMRoute("https://registry.npmjs.org"), request.URL.String(), current.Add(-5*time.Second), current)
	if reason != "" || !expiry.Equal(current.Add(10*time.Second)) || response.Header.Get("Age") != "50" {
		t.Fatalf("expiry=%s age=%q", expiry, response.Header.Get("Age"))
	}
}

type npmDelayedBody struct {
	io.Reader
	advance func()
}

func (body *npmDelayedBody) Read(p []byte) (int, error) {
	if body.advance != nil {
		body.advance()
		body.advance = nil
	}
	return body.Reader.Read(p)
}

func (*npmDelayedBody) Close() error { return nil }
