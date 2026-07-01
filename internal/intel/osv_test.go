package intel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

func TestOSVProviderRejectsOversizedSuccessResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat(" ", maxOSVResponseBytes+1))
	}))
	defer server.Close()

	provider := NewOSVProvider(server.URL, time.Second, time.Minute)
	_, err := provider.Query(context.Background(), policy.Package{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "osv response exceeds") {
		t.Fatalf("err = %v, want oversized response error", err)
	}
}

func TestOSVProviderRejectsTooManyFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := osvResponse{Vulns: make([]osvVulnerability, maxOSVFindings+1)}
		for i := range response.Vulns {
			response.Vulns[i].ID = "OSV-TEST"
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	provider := NewOSVProvider(server.URL, time.Second, time.Minute)
	_, err := provider.Query(context.Background(), policy.Package{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"})
	if err == nil || !strings.Contains(err.Error(), "vulnerabilities") {
		t.Fatalf("err = %v, want too many findings error", err)
	}
}

func TestOSVProviderDecodesBoundedSuccessResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := osvResponse{Vulns: []osvVulnerability{{
			ID:      "OSV-TEST",
			Summary: "test finding",
			Severity: []osvSeverity{{
				Type:  "CVSS_V3",
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8",
			}},
		}}}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Fatal(err)
		}
	}))
	defer server.Close()

	provider := NewOSVProvider(server.URL, time.Second, time.Minute)
	result, err := provider.Query(context.Background(), policy.Package{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	if result.Findings[0].Severity != 9.8 {
		t.Fatalf("severity = %.1f, want 9.8", result.Findings[0].Severity)
	}
}
