package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

func TestProxyCachesPublicNPMArtifactsWithCDNCookies(t *testing.T) {
	for _, cookies := range [][]string{
		{"__cf_bm=bot; Path=/; HttpOnly; Secure; SameSite=None"},
		{"_cfuvid=visitor; Path=/; HttpOnly; Secure; SameSite=None"},
		{"__cf_bm=bot; Path=/; HttpOnly; Secure", "_cfuvid=visitor; Path=/; HttpOnly; Secure"},
	} {
		t.Run(strings.Join(cookies, ","), func(t *testing.T) {
			store := newMemoryArtifactStore()
			metrics := newTestCacheMetrics()
			upstreamCalls := 0
			transport := npmCookieTransport(func(request *http.Request) (*http.Response, error) {
				upstreamCalls++
				return npmCookieResponse(request, cookies), nil
			})
			for _, want := range []string{"MISS", "HIT"} {
				proxy := newTestCachingProxy(t, store, metrics, 1024)
				proxy.client = &http.Client{Transport: transport}
				recorder := httptest.NewRecorder()
				_, err := proxy.Serve(recorder, httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil), testNPMRoute("https://registry.npmjs.org"), exactArtifactInfo())
				if err != nil {
					t.Fatal(err)
				}
				if recorder.Code != http.StatusOK || recorder.Body.String() != "artifact" || recorder.Header().Get(cacheHeader) != want {
					t.Fatalf("response = %d %q %q, want 200 artifact %s", recorder.Code, recorder.Body.String(), recorder.Header().Get(cacheHeader), want)
				}
				if len(recorder.Header().Values("Set-Cookie")) != 0 {
					t.Fatal("CDN cookies were forwarded to the client")
				}
			}
			if upstreamCalls != 1 || store.putCalls != 1 || metrics.hits["npm"] != 1 || len(metrics.bypasses) != 0 {
				t.Fatalf("upstream=%d stores=%d hits=%v bypasses=%v", upstreamCalls, store.putCalls, metrics.hits, metrics.bypasses)
			}
			for _, entry := range store.entries {
				if len(entry.headers.Values("Set-Cookie")) != 0 {
					t.Fatal("CDN cookies were stored")
				}
			}
		})
	}
}

func TestProxyPreservesNPMCookieCacheSafetyGates(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		mutate   func(*http.Request, *http.Response, *config.RouteConfig, *registry.RequestInfo)
	}{
		{name: "insecure upstream", upstream: "http://registry.npmjs.org"},
		{name: "other registry", upstream: "https://registry.example.com"},
		{name: "lookalike registry", upstream: "https://registry.npmjs.org.example.com"},
		{name: "custom port", upstream: "https://registry.npmjs.org:8443"},
		{name: "URL credentials", upstream: "https://user:password@registry.npmjs.org"},
		{name: "configured upstream query", upstream: "https://registry.npmjs.org?token=private"},
		{name: "other ecosystem", mutate: func(_ *http.Request, _ *http.Response, route *config.RouteConfig, _ *registry.RequestInfo) {
			route.Ecosystem = "maven"
		}},
		{name: "upstream token", mutate: func(_ *http.Request, _ *http.Response, route *config.RouteConfig, _ *registry.RequestInfo) {
			route.UpstreamTokenEnv = "NPM_CACHE_TEST_TOKEN"
		}},
		{name: "client cookie", mutate: func(r *http.Request, _ *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			r.Header.Set("Cookie", "session=private")
		}},
		{name: "query", mutate: func(r *http.Request, _ *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			r.URL.RawQuery = "version=1"
		}},
		{name: "range", mutate: func(r *http.Request, _ *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			r.Header.Set("Range", "bytes=0-1")
		}},
		{name: "metadata", mutate: func(_ *http.Request, _ *http.Response, _ *config.RouteConfig, info *registry.RequestInfo) {
			info.Kind = "metadata"
		}},
		{name: "unknown cookie", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Add("Set-Cookie", "session=private")
		}},
		{name: "cookie name is case sensitive", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Set-Cookie", "__CF_BM=bot")
		}},
		{name: "malformed cookie", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Add("Set-Cookie", "not-a-cookie")
		}},
		{name: "empty cookie", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Set-Cookie", "")
		}},
		{name: "malformed attribute", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Set-Cookie", "__cf_bm=bot; Max-Age=invalid")
		}},
		{name: "not public", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Cache-Control", "immutable, max-age=3600")
		}},
		{name: "not immutable", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Cache-Control", "public, max-age=3600")
		}},
		{name: "invalid public directive", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Cache-Control", "public=false, immutable")
		}},
		{name: "private", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Add("Cache-Control", "private")
		}},
		{name: "no store", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Add("Cache-Control", "no-store")
		}},
		{name: "no cache", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Add("Cache-Control", "no-cache")
		}},
		{name: "varies on cookies", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Vary", "Cookie")
		}},
		{name: "encoded", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Content-Encoding", "gzip")
		}},
		{name: "partial response", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.StatusCode = http.StatusPartialContent
		}},
		{name: "content range", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.Header.Set("Content-Range", "bytes 0-7/20")
		}},
		{name: "oversized", mutate: func(_ *http.Request, resp *http.Response, _ *config.RouteConfig, _ *registry.RequestInfo) {
			resp.ContentLength = 2048
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newMemoryArtifactStore()
			proxy := newTestCachingProxy(t, store, newTestCacheMetrics(), 1024)
			upstream := test.upstream
			if upstream == "" {
				upstream = "https://registry.npmjs.org"
			}
			route := testNPMRoute(upstream)
			info := exactArtifactInfo()
			request := httptest.NewRequest(http.MethodGet, "/npm/pkg/-/pkg-1.0.0.tgz", nil)
			response := npmCookieResponse(nil, []string{"__cf_bm=bot; Secure", "_cfuvid=visitor; Secure"})
			if test.mutate != nil {
				test.mutate(request, response, &route, &info)
			}
			cookies := response.Header.Values("Set-Cookie")
			upstreamCalls := 0
			proxy.client = &http.Client{Transport: npmCookieTransport(func(req *http.Request) (*http.Response, error) {
				upstreamCalls++
				copy := *response
				copy.Header = response.Header.Clone()
				copy.Body = io.NopCloser(strings.NewReader("artifact"))
				copy.Request = req
				return &copy, nil
			})}
			for range 2 {
				recorder := httptest.NewRecorder()
				if _, err := proxy.Serve(recorder, request, route, info); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(recorder.Header().Values("Set-Cookie"), cookies) {
					t.Fatal("bypassed response cookies were changed")
				}
				if recorder.Header().Get(cacheHeader) == "HIT" {
					t.Fatal("ineligible response served from cache")
				}
			}
			if store.putCalls != 0 || upstreamCalls != 2 {
				t.Fatalf("stores=%d upstream=%d, want 0 and 2", store.putCalls, upstreamCalls)
			}
		})
	}
}

func TestProxyDoesNotStripCDNCookiesAfterRedirect(t *testing.T) {
	proxy := newTestCachingProxy(t, newMemoryArtifactStore(), newTestCacheMetrics(), 1024)
	target := "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
	request := &http.Request{URL: &url.URL{Scheme: "https", Host: "registry.npmjs.org", Path: "/other"}}
	response := npmCookieResponse(request, []string{"__cf_bm=bot"})
	proxy.stripCacheableNPMCDNCookies(response, testNPMRoute("https://registry.npmjs.org"), target)
	if len(response.Cookies()) != 1 {
		t.Fatal("redirected response cookies were stripped")
	}
}

func TestProxyDoesNotStripCDNCookiesFromAuthenticatedUpstreamResponses(t *testing.T) {
	for _, header := range []string{"Authorization", "Cookie"} {
		t.Run(header, func(t *testing.T) {
			proxy := newTestCachingProxy(t, newMemoryArtifactStore(), newTestCacheMetrics(), 1024)
			target := "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
			request := httptest.NewRequest(http.MethodGet, target, nil)
			request.Header.Set(header, "private")
			response := npmCookieResponse(request, []string{"__cf_bm=bot"})
			proxy.stripCacheableNPMCDNCookies(response, testNPMRoute("https://registry.npmjs.org"), target)
			if len(response.Cookies()) != 1 {
				t.Fatal("authenticated response cookies were stripped")
			}
		})
	}
}

type npmCookieTransport func(*http.Request) (*http.Response, error)

func (transport npmCookieTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func npmCookieResponse(request *http.Request, cookies []string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Cache-Control": {"public, immutable, max-age=31557600"},
			"Set-Cookie":    cookies,
			"Content-Type":  {"application/octet-stream"},
		},
		ContentLength: 8,
		Body:          io.NopCloser(strings.NewReader("artifact")),
		Request:       request,
	}
}
