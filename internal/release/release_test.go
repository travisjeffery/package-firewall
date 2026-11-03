package release

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/registry"
)

func registryServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer upstream-token" {
			t.Errorf("authorization = %q", got)
		}
		switch r.URL.EscapedPath() {
		case "/npm/@scope%2Fpkg":
			if r.Header.Get("Accept") != "application/json" {
				t.Errorf("npm accept = %q, the abbreviated packument has no time", r.Header.Get("Accept"))
			}
			// "versions" precedes "time" and must be skipped, nested objects included.
			fmt.Fprint(w, `{"name":"@scope/pkg","versions":{"1.0.0":{"dist":{"tarball":"x"},"keywords":["a",{"b":[1]}]}},"time":{"created":"2020-01-01T00:00:00.000Z","1.0.0":"2026-11-02T10:00:00.000Z"}}`)
		case "/pypi/simple/requests/":
			if r.Header.Get("Accept") != "application/vnd.pypi.simple.v1+json" {
				t.Errorf("pypi accept = %q", r.Header.Get("Accept"))
			}
			fmt.Fprint(w, `{"files":[{"filename":"requests-2.32.0.tar.gz","upload-time":"2024-05-20T00:00:00.000000Z"},{"filename":"requests-2.32.0-py3-none-any.whl","upload-time":"2026-11-02T11:00:00.123456Z"}]}`)
		case "/go/golang.org/x/mod/@v/v0.20.0.info":
			fmt.Fprint(w, `{"Version":"v0.20.0","Time":"2026-11-02T12:00:00Z"}`)
		case "/maven/com/example/lib/1.0/lib-1.0.jar":
			if r.Method != http.MethodHead {
				t.Errorf("maven method = %s", r.Method)
			}
			w.Header().Set("Last-Modified", "Mon, 02 Nov 2026 13:00:00 GMT")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("PFW_TEST_UPSTREAM_TOKEN", "upstream-token")
	return srv, &requests
}

func TestPublishedAtPerEcosystem(t *testing.T) {
	srv, _ := registryServer(t)
	resolver := NewResolver(srv.Client())
	for _, tt := range []struct {
		route registry.Route
		path  string
		want  string
	}{
		{registry.Route{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: srv.URL + "/npm/"}, "/npm/@scope/pkg/-/pkg-1.0.0.tgz", "2026-11-02T10:00:00Z"},
		// The wheel's own upload time, not the release's first file.
		{registry.Route{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: srv.URL + "/pypi/"}, "/pypi/files/packages/aa/requests-2.32.0-py3-none-any.whl", "2026-11-02T11:00:00.123456Z"},
		{registry.Route{Name: "go", Ecosystem: "go", PathPrefix: "/go/", UpstreamURL: srv.URL + "/go/"}, "/go/golang.org/x/mod/@v/v0.20.0.zip", "2026-11-02T12:00:00Z"},
		{registry.Route{Name: "maven", Ecosystem: "maven", PathPrefix: "/maven/", UpstreamURL: srv.URL + "/maven/"}, "/maven/com/example/lib/1.0/lib-1.0.jar", "2026-11-02T13:00:00Z"},
	} {
		t.Run(tt.route.Ecosystem, func(t *testing.T) {
			tt.route.UpstreamTokenEnv = "PFW_TEST_UPSTREAM_TOKEN"
			info := registry.Identify(tt.route, tt.path)
			got, err := resolver.PublishedAt(context.Background(), tt.route, info)
			if err != nil {
				t.Fatal(err)
			}
			if want, _ := time.Parse(time.RFC3339Nano, tt.want); !got.Equal(want) {
				t.Fatalf("published = %s, want %s", got, want)
			}
		})
	}
}

func TestPublishedAtIsCached(t *testing.T) {
	srv, requests := registryServer(t)
	resolver := NewResolver(srv.Client())
	route := registry.Route{Name: "go", Ecosystem: "go", PathPrefix: "/go/", UpstreamURL: srv.URL + "/go/", UpstreamTokenEnv: "PFW_TEST_UPSTREAM_TOKEN"}
	info := registry.Identify(route, "/go/golang.org/x/mod/@v/v0.20.0.zip")
	for range 3 {
		if _, err := resolver.PublishedAt(context.Background(), route, info); err != nil {
			t.Fatal(err)
		}
	}
	if *requests != 1 {
		t.Fatalf("upstream requests = %d", *requests)
	}
}

func TestPublishedAtFailsWhenTheVersionIsMissing(t *testing.T) {
	srv, _ := registryServer(t)
	resolver := NewResolver(srv.Client())
	for _, tt := range []struct {
		route registry.Route
		path  string
		want  string
	}{
		{registry.Route{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: srv.URL + "/npm/"}, "/npm/@scope/pkg/-/pkg-2.0.0.tgz", "has no time for 2.0.0"},
		{registry.Route{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: srv.URL + "/pypi/"}, "/pypi/files/packages/aa/requests-9.0.0.tar.gz", "does not list"},
		{registry.Route{Name: "maven", Ecosystem: "maven", PathPrefix: "/maven/", UpstreamURL: srv.URL + "/maven/"}, "/maven/com/example/lib/2.0/lib-2.0.jar", "returned 404"},
	} {
		t.Run(tt.route.Ecosystem, func(t *testing.T) {
			tt.route.UpstreamTokenEnv = "PFW_TEST_UPSTREAM_TOKEN"
			_, err := resolver.PublishedAt(context.Background(), tt.route, registry.Identify(tt.route, tt.path))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPublishedAtIsUnknownForEcosystemsWithoutASource(t *testing.T) {
	route := registry.Route{Name: "gradle", Ecosystem: "static", PathPrefix: "/build-assets/gradle/", UpstreamURL: "http://unused.invalid/"}
	info := registry.Identify(route, "/build-assets/gradle/gradle-9.1.0-bin.zip")
	got, err := NewResolver(http.DefaultClient).PublishedAt(context.Background(), route, info)
	if err != nil || !got.IsZero() {
		t.Fatalf("published = %s, err = %v", got, err)
	}
}
