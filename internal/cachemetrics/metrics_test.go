package cachemetrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsExposeRequiredCacheOutcomes(t *testing.T) {
	metrics := New()
	metrics.Hit("npm")
	metrics.Miss("npm")
	metrics.StoreError("npm")
	metrics.ReadError("npm")
	metrics.Bypass("npm", "range")
	metrics.CacheFillLeader("npm")
	metrics.CacheFillWaiter("npm", "cluster")
	metrics.UpstreamRequest("npm", "429")
	metrics.UpstreamInFlight("npm", 2)
	metrics.UpstreamInFlight("npm", -1)
	metrics.UpstreamRetry("npm", "rate_limited")
	metrics.UpstreamThrottled("npm", "cooldown")

	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "version=0.0.4") {
		t.Fatalf("content type = %q", got)
	}
	for _, line := range []string{
		`package_firewall_cache_hits_total{route="npm"} 1`,
		`package_firewall_cache_misses_total{route="npm"} 1`,
		`package_firewall_cache_store_errors_total{route="npm"} 1`,
		`package_firewall_cache_read_errors_total{route="npm"} 1`,
		`package_firewall_cache_bypasses_total{route="npm",reason="range"} 1`,
		`package_firewall_cache_fill_leaders_total{route="npm"} 1`,
		`package_firewall_cache_fill_waiters_total{route="npm",scope="cluster"} 1`,
		`package_firewall_upstream_requests_total{route="npm",status="429"} 1`,
		`package_firewall_upstream_in_flight{route="npm"} 1`,
		`package_firewall_upstream_retries_total{route="npm",reason="rate_limited"} 1`,
		`package_firewall_upstream_throttled_total{route="npm",reason="cooldown"} 1`,
	} {
		if !strings.Contains(recorder.Body.String(), line) {
			t.Fatalf("metrics missing %q:\n%s", line, recorder.Body.String())
		}
	}
}

func TestMetricsEscapeLabelValues(t *testing.T) {
	metrics := New()
	metrics.Bypass("route\nname", `quoted"reason`)
	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(recorder.Body.String(), `route="route\nname",reason="quoted\"reason"`) {
		t.Fatalf("labels were not escaped:\n%s", recorder.Body.String())
	}
}
