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
