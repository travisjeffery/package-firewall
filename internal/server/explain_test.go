package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/travisjeffery/tidewaiter/internal/config"
	"github.com/travisjeffery/tidewaiter/internal/explain"
	"github.com/travisjeffery/tidewaiter/internal/intel"
	"github.com/travisjeffery/tidewaiter/internal/policy"
)

type fixedProvider struct {
	findings map[string][]intel.Finding
	queries  int
}

func (p *fixedProvider) Query(_ context.Context, pkg policy.Package) (intel.Result, error) {
	p.queries++
	return intel.Result{Findings: p.findings[pkg.PURL]}, nil
}

func shellQuoteServer(t *testing.T) (http.Handler, *fixedProvider) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("blocked artifact reached upstream")
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("PFW_TEST_EXPLAIN_USER", "ci")
	t.Setenv("PFW_TEST_EXPLAIN_PASS", "secret")
	cfg := config.Default()
	cfg.Auth.BasicUsernameEnv = "PFW_TEST_EXPLAIN_USER"
	cfg.Auth.BasicPasswordEnv = "PFW_TEST_EXPLAIN_PASS"
	cfg.Decision.ExceptionsURL = "https://example.test/exceptions"
	cfg.Routes = []config.RouteConfig{
		{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: upstream.URL + "/"},
		{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: upstream.URL + "/", FileUpstreamURL: upstream.URL + "/"},
	}
	engine, err := policy.New(policy.Config{Deny: []string{"pkg:pypi/evil@*"}})
	if err != nil {
		t.Fatal(err)
	}
	provider := &fixedProvider{findings: map[string][]intel.Finding{
		"pkg:npm/shell-quote@1.9.0": {{
			ID:       "GHSA-pqg4-j6r4-53mv",
			Aliases:  []string{"CVE-2026-102422"},
			Summary:  "quote() command injection",
			Severity: 9.2,
			Affected: []string{"<1.11.0"},
			Fixed:    []string{"1.11.0"},
		}},
		"pkg:npm/flatmap-stream@0.1.1": {{
			ID:      "MAL-2025-20690",
			Summary: "Malicious code in flatmap-stream (npm)",
		}},
	}}
	return New(cfg, engine, provider).routesHandler(), provider
}

func authed(req *http.Request) *http.Request {
	req.SetBasicAuth("ci", "secret")
	return req
}

func TestBlockedResponseExplainsTheAdvisory(t *testing.T) {
	handler, _ := shellQuoteServer(t)
	req := authed(httptest.NewRequest(http.MethodGet, "/npm/shell-quote/-/shell-quote-1.9.0.tgz", nil))
	req.Header.Set("X-Request-ID", "req-42")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Error       string              `json:"error"`
		Code        string              `json:"code"`
		Reason      string              `json:"reason"`
		PURL        string              `json:"purl"`
		RequestID   string              `json:"request_id"`
		Explanation explain.Explanation `json:"explanation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Blocked by Tidewaiter: shell-quote@1.9.0", "GHSA-pqg4-j6r4-53mv (CVE-2026-102422)", "severity 9.2 >= threshold 9.0", "Fixed in 1.11.0", "Request ID: req-42", "Exceptions: https://example.test/exceptions"} {
		if !strings.Contains(body.Error, want) {
			t.Errorf("error %q missing %q", body.Error, want)
		}
	}
	if body.Code != "blocked" || body.PURL != "pkg:npm/shell-quote@1.9.0" || body.RequestID != "req-42" {
		t.Errorf("body = %+v", body)
	}
	if body.Reason != "vulnerability GHSA-pqg4-j6r4-53mv severity 9.2 exceeds threshold 9.0" {
		t.Errorf("reason = %q, the audit log format must not change", body.Reason)
	}
	if body.Explanation.Advisory == nil || body.Explanation.Advisory.Fixed[0] != "1.11.0" {
		t.Errorf("explanation = %+v", body.Explanation)
	}
	if got := rec.Header().Get("X-Package-Firewall-Advisory"); got != "GHSA-pqg4-j6r4-53mv,CVE-2026-102422" {
		t.Errorf("advisory header = %q", got)
	}
	if got := rec.Header().Get("X-Package-Firewall-Request-Id"); got != "req-42" {
		t.Errorf("request id header = %q", got)
	}
	if got := rec.Header().Get("X-Package-Firewall-Reason"); !strings.HasPrefix(got, "Blocked by Tidewaiter: shell-quote@1.9.0 has GHSA") {
		t.Errorf("reason header = %q", got)
	}
}

func TestMaliciousPackageIsBlockedUnderTheDefaultWarnAction(t *testing.T) {
	handler, _ := shellQuoteServer(t)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, authed(httptest.NewRequest(http.MethodGet, "/npm/flatmap-stream/-/flatmap-stream-0.1.1.tgz", nil)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Reason      string              `json:"reason"`
		Explanation explain.Explanation `json:"explanation"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Reason != "malicious package MAL-2025-20690" || body.Explanation.Kind != "malware" {
		t.Fatalf("body = %+v", body)
	}
	if !strings.Contains(body.Explanation.Message, "known malicious package (MAL-2025-20690)") {
		t.Errorf("message = %q", body.Explanation.Message)
	}
}

func TestExplainByFailedURL(t *testing.T) {
	handler, _ := shellQuoteServer(t)
	target := url.QueryEscape("https://packages.example.com/npm/shell-quote/-/shell-quote-1.9.0.tgz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, authed(httptest.NewRequest(http.MethodGet, "/explain?url="+target, nil)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	var e explain.Explanation
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if !e.Blocked || e.Kind != "vulnerability" || e.Package != "shell-quote@1.9.0" || !strings.Contains(e.Message, "Fixed in 1.11.0") {
		t.Fatalf("explanation = %+v", e)
	}
}

func TestExplainByPURLAndAsText(t *testing.T) {
	handler, _ := shellQuoteServer(t)
	for _, tt := range []struct {
		query string
		want  string
	}{
		{"purl=pkg:pypi/evil@1.0", "Blocked by Tidewaiter: evil@1.0 matches deny rule pkg:pypi/evil@*."},
		{"purl=pkg:npm/shell-quote@1.12.0", "Tidewaiter allows shell-quote@1.12.0: policy and intel allowed package."},
		{"url=" + url.QueryEscape("/pypi/files/aa/bb/evil-1.0-py3-none-any.whl"), "Blocked by Tidewaiter: evil@1.0 matches deny rule"},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, authed(httptest.NewRequest(http.MethodGet, "/explain?format=text&"+tt.query, nil)))
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), tt.want) {
			t.Fatalf("%s: status = %d body = %q, want prefix %q", tt.query, rec.Code, rec.Body.String(), tt.want)
		}
	}
}

func TestExplainRejectsBadRequests(t *testing.T) {
	handler, _ := shellQuoteServer(t)
	for _, tt := range []struct {
		name   string
		req    *http.Request
		status int
	}{
		{"anonymous", httptest.NewRequest(http.MethodGet, "/explain?purl=pkg:npm/shell-quote@1.9.0", nil), http.StatusUnauthorized},
		{"no target", authed(httptest.NewRequest(http.MethodGet, "/explain", nil)), http.StatusBadRequest},
		{"bad purl", authed(httptest.NewRequest(http.MethodGet, "/explain?purl=pkg:npm/shell-quote", nil)), http.StatusBadRequest},
		{"unrouted url", authed(httptest.NewRequest(http.MethodGet, "/explain?url=/nope/x", nil)), http.StatusBadRequest},
		{"metadata url", authed(httptest.NewRequest(http.MethodGet, "/explain?url=/npm/shell-quote", nil)), http.StatusBadRequest},
		{"post", authed(httptest.NewRequest(http.MethodPost, "/explain?purl=pkg:npm/shell-quote@1.9.0", nil)), http.StatusMethodNotAllowed},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, tt.req)
		if rec.Code != tt.status {
			t.Errorf("%s: status = %d, want %d (body %s)", tt.name, rec.Code, tt.status, rec.Body.String())
		}
		if tt.status == http.StatusOK && !strings.Contains(rec.Body.String(), `"blocked":true`) {
			t.Errorf("%s: body = %s, want a blocked explanation", tt.name, rec.Body.String())
		}
	}
}

func TestExplainIsRateLimited(t *testing.T) {
	handler, provider := shellQuoteServer(t)
	limited := 0
	for range explainBurst + 5 {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, authed(httptest.NewRequest(http.MethodGet, "/explain?purl=pkg:npm/shell-quote@1.9.0", nil)))
		if rec.Code == http.StatusTooManyRequests {
			limited++
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("429 without Retry-After")
			}
		}
	}
	if limited == 0 {
		t.Fatal("no request was rate limited")
	}
	if provider.queries > explainBurst+1 {
		t.Fatalf("intel queried %d times past the limit", provider.queries)
	}
}

func TestExplainHonorsAnonymousRoutes(t *testing.T) {
	cfg := anonymousBuildAssetConfig(t, "http://upstream.invalid")
	engine, err := policy.New(policy.Config{Deny: []string{"pkg:generic/gradle-9.1.0-bin.zip@*"}})
	if err != nil {
		t.Fatal(err)
	}
	handler := New(cfg, engine, intel.NoopProvider{}).routesHandler()
	for _, tt := range []struct {
		name   string
		query  string
		status int
	}{
		{"anonymous route url", "url=" + url.QueryEscape("/build-assets/gradle/gradle-9.1.0-bin.zip"), http.StatusOK},
		{"authenticated route url", "url=" + url.QueryEscape("/npm/shell-quote/-/shell-quote-1.9.0.tgz"), http.StatusUnauthorized},
		{"purl", "purl=pkg:npm/shell-quote@1.9.0", http.StatusUnauthorized},
		{"unrouted url", "url=/nope/x", http.StatusUnauthorized},
		{"no target", "", http.StatusUnauthorized},
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/explain?"+tt.query, nil))
		if rec.Code != tt.status {
			t.Errorf("%s: status = %d, want %d (body %s)", tt.name, rec.Code, tt.status, rec.Body.String())
		}
		if tt.status == http.StatusOK && !strings.Contains(rec.Body.String(), `"blocked":true`) {
			t.Errorf("%s: body = %s, want a blocked explanation", tt.name, rec.Body.String())
		}
	}
}
