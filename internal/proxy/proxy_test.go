package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

func TestNewHTTPClientUsesBoundedTimeouts(t *testing.T) {
	client := NewHTTPClient(2*time.Minute, 15*time.Second)
	if client.Timeout != 2*time.Minute {
		t.Fatalf("request timeout = %s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", client.Transport)
	}
	if transport.ResponseHeaderTimeout != 15*time.Second {
		t.Fatalf("response header timeout = %s", transport.ResponseHeaderTimeout)
	}
}

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

func TestProxyRewritesPyPIIndexWhenClientAcceptsGzip(t *testing.T) {
	var upstreamEncoding string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
		_, _ = w.Write([]byte(`{"files":[{"url":"https://files.pythonhosted.org/packages/six-1.16.0-py2.py3-none-any.whl"}]}`))
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: upstream.URL + "/"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/pypi/simple/six/", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	if _, err := p.Serve(rec, req, route, registry.RequestInfo{UpstreamPath: "/simple/six/"}); err != nil {
		t.Fatal(err)
	}
	if upstreamEncoding != "identity" {
		t.Fatalf("upstream Accept-Encoding = %q, want identity", upstreamEncoding)
	}
	if strings.Contains(rec.Body.String(), "files.pythonhosted.org") {
		t.Fatalf("download URL escaped the firewall: %s", rec.Body.String())
	}
}

func TestProxyRefusesSplitContentEncodingFields(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Add("Content-Encoding", "identity")
		w.Header().Add("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("not really gzip"))
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: upstream.URL + "/"}
	_, err := p.Serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/pypi/simple/six/", nil), route, registry.RequestInfo{UpstreamPath: "/simple/six/"})
	if !errors.Is(err, errEncodedRewriteBody) {
		t.Fatalf("err = %v, want errEncodedRewriteBody", err)
	}
}

func TestProxyKeepsClientEncodingNegotiationForArtifacts(t *testing.T) {
	var upstreamEncoding string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("wheel"))
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: upstream.URL + "/", FileUpstreamURL: upstream.URL + "/"}
	req := httptest.NewRequest(http.MethodGet, "/pypi/files/packages/six-1.17.0-py2.py3-none-any.whl", nil)
	req.Header.Set("Accept-Encoding", "gzip, identity;q=0")
	info := registry.RequestInfo{Kind: "artifact", FileUpstream: true, UpstreamPath: "/packages/six-1.17.0-py2.py3-none-any.whl"}
	if _, err := p.Serve(httptest.NewRecorder(), req, route, info); err != nil {
		t.Fatal(err)
	}
	if upstreamEncoding != "gzip, identity;q=0" {
		t.Fatalf("upstream Accept-Encoding = %q, want the client's", upstreamEncoding)
	}
}

func TestIdentityContentEncoding(t *testing.T) {
	for _, tt := range []struct {
		values []string
		ok     bool
	}{
		{nil, true},
		{[]string{"identity"}, true},
		{[]string{"Identity, identity"}, true},
		{[]string{"gzip"}, false},
		{[]string{"identity", "gzip"}, false},
		{[]string{"identity, br"}, false},
	} {
		if _, ok := identityContentEncoding(tt.values); ok != tt.ok {
			t.Errorf("%v: ok = %v, want %v", tt.values, ok, tt.ok)
		}
	}
}

func TestProxyRewritesAbbreviatedNPMMetadata(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.npm.install-v1+json")
		_, _ = w.Write([]byte(`{"versions":{"1.9.0":{"dist":{"tarball":"https://registry.npmjs.org/shell-quote/-/shell-quote-1.9.0.tgz"}}}}`))
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/npm/shell-quote", nil)
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*")
	if _, err := p.Serve(rec, req, route, registry.RequestInfo{UpstreamPath: "/shell-quote"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), `"tarball":"http://firewall.test/npm/shell-quote/-/shell-quote-1.9.0.tgz"`) {
		t.Fatalf("tarball URL escaped the firewall: %s", rec.Body.String())
	}
}

func TestProxyRefusesEncodedBodyItCannotRewrite(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write([]byte("not really gzip"))
	}))
	defer upstream.Close()
	p := New("http://firewall.test")
	route := config.RouteConfig{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: upstream.URL + "/"}
	rec := httptest.NewRecorder()
	_, err := p.Serve(rec, httptest.NewRequest(http.MethodGet, "/pypi/simple/six/", nil), route, registry.RequestInfo{UpstreamPath: "/simple/six/"})
	if !errors.Is(err, errEncodedRewriteBody) {
		t.Fatalf("err = %v, want errEncodedRewriteBody", err)
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

func TestUpstreamRedirectPolicyStopsAfterTenHops(t *testing.T) {
	checkRedirect, err := upstreamRedirectPolicy(false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	origin := mustParseURL(t, "https://registry.example/loop")
	via := make([]*http.Request, maxUpstreamRedirects)
	for index := range via {
		via[index] = &http.Request{URL: origin}
	}
	err = checkRedirect(&http.Request{URL: origin}, via)
	if !errors.Is(err, errUpstreamRedirectLimit) {
		t.Fatalf("error = %v", err)
	}
}

func TestUpstreamRedirectPolicyRejectsSchemeChange(t *testing.T) {
	checkRedirect, err := upstreamRedirectPolicy(true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	via := []*http.Request{{URL: mustParseURL(t, "https://registry.example/pkg")}}
	err = checkRedirect(&http.Request{URL: mustParseURL(t, "http://registry.example/pkg")}, via)
	if !errors.Is(err, errUnsafeUpstreamRedirect) {
		t.Fatalf("error = %v", err)
	}
}

func TestProxyRejectsUnapprovedRedirectOrigin(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/pkg", http.StatusFound)
	}))
	defer upstream.Close()

	proxy := New("http://firewall.test")
	route := config.RouteConfig{
		Ecosystem:              "npm",
		PathPrefix:             "/npm/",
		UpstreamURL:            upstream.URL + "/",
		EnforceRedirectOrigins: true,
	}
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
	_, err := proxy.Serve(httptest.NewRecorder(), request, route, registry.RequestInfo{UpstreamPath: "/pkg"})
	if !errors.Is(err, errUnsafeUpstreamRedirect) {
		t.Fatalf("error = %v", err)
	}
	if targetHit {
		t.Fatal("unapproved redirect target was reached")
	}
}

func TestProxyAllowsAndObservesCrossOriginRedirectByDefault(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/pkg", http.StatusFound)
	}))
	defer upstream.Close()

	var logs bytes.Buffer
	proxy := New(
		"http://firewall.test",
		WithLogger(slog.New(slog.NewJSONHandler(&logs, nil))),
	)
	route := config.RouteConfig{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
	if _, err := proxy.Serve(recorder, request, route, registry.RequestInfo{UpstreamPath: "/pkg"}); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
	}
	var event map[string]any
	if err := json.NewDecoder(&logs).Decode(&event); err != nil {
		t.Fatal(err)
	}
	initialOrigin, err := config.NormalizeHTTPOrigin(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	redirectOrigin, err := config.NormalizeHTTPOrigin(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	if event["msg"] != "upstream_cross_origin_redirect" || event["route"] != "npm" || event["initial_origin"] != initialOrigin || event["redirect_origin"] != redirectOrigin || event["enforced"] != false {
		t.Fatalf("event = %#v", event)
	}
}

func TestProxyAllowsSameOriginRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte("ok"))
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer upstream.Close()

	proxy := New("http://firewall.test")
	route := config.RouteConfig{Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/start", nil)
	if _, err := proxy.Serve(recorder, request, route, registry.RequestInfo{UpstreamPath: "/start"}); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
	}
}

func TestProxyAllowsConfiguredRedirectOrigin(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/pkg", http.StatusFound)
	}))
	defer upstream.Close()

	proxy := New("http://firewall.test")
	route := config.RouteConfig{
		Ecosystem:              "npm",
		PathPrefix:             "/npm/",
		UpstreamURL:            upstream.URL + "/",
		EnforceRedirectOrigins: true,
		AllowedRedirectOrigins: []string{target.URL},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
	if _, err := proxy.Serve(recorder, request, route, registry.RequestInfo{UpstreamPath: "/pkg"}); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "ok" {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
	}
}

func TestProxyRejectsRedirectThatRequiresReplayingStreamingBody(t *testing.T) {
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL+"/upload")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer upstream.Close()

	proxy := New("http://firewall.test")
	route := config.RouteConfig{Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/npm/pkg", strings.NewReader("body"))
	_, err := proxy.Serve(recorder, request, route, registry.RequestInfo{UpstreamPath: "/pkg"})
	if !errors.Is(err, errUnreplayableBodyRedirect) {
		t.Fatalf("error = %v", err)
	}
	if targetHit {
		t.Fatal("redirect target was reached")
	}
	if location := recorder.Header().Get("Location"); location != "" {
		t.Fatalf("Location = %q", location)
	}
}

func TestProxyAllowsBodyWithinConfiguredRequestTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("complete"))
	}))
	defer upstream.Close()

	proxy := New(
		"http://firewall.test",
		WithHTTPClient(NewHTTPClient(time.Second, 20*time.Millisecond)),
	)
	route := config.RouteConfig{Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/npm/pkg", nil)
	if _, err := proxy.Serve(recorder, request, route, registry.RequestInfo{UpstreamPath: "/pkg"}); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || recorder.Body.String() != "complete" {
		t.Fatalf("status = %d body = %q", recorder.Code, recorder.Body.String())
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
	req.Header.Set("Cf-Access-Authenticated-User-Email", "alice@example.com")
	req.Header.Set("X-Amzn-Oidc-Data", "oidc")
	req.Header.Set("X-Auth-Request-User", "alice")
	req.Header.Set("X-Forwarded-Email", "alice@example.com")
	req.Header.Set("X-Forwarded-Access-Token", "token")
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("Accept", "application/octet-stream")
	_, err := p.Serve(httptest.NewRecorder(), req, route, registry.RequestInfo{UpstreamPath: "/pkg/-/pkg-1.0.0.tgz"})
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"Authorization", "Cookie", "Cf-Access-Jwt-Assertion", "Cf-Access-Authenticated-User-Email", "X-Amzn-Oidc-Data", "X-Auth-Request-User", "X-Forwarded-Access-Token", "X-Forwarded-Email", "X-Forwarded-User"} {
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

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
