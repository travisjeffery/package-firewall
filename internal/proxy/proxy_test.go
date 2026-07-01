package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/travisjeffery/package-firewall/internal/config"
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
