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
				Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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

func TestOSVProviderKeepsAliasesAndRangesForTheQueriedPackage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"vulns":[{
			"id":"GHSA-pqg4-j6r4-53mv",
			"aliases":["CVE-2026-102422"],
			"summary":"quote() command injection",
			"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
			"affected":[
				{"package":{"ecosystem":"npm","name":"other"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"9.9.9"}]}]},
				{"package":{"ecosystem":"npm","name":"shell-quote"},"ranges":[
					{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.8.5"},{"introduced":"1.9.0"},{"fixed":"1.11.0"}]},
					{"type":"GIT","events":[{"introduced":"0"},{"fixed":"abc123"}]},
					{"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"last_affected":"2.0.3"}]},
					{"type":"ECOSYSTEM","events":[{"introduced":"3.0.0"}]}
				]}
			]
		}]}`)
	}))
	defer server.Close()

	provider := NewOSVProvider(server.URL, time.Second, time.Minute)
	result, err := provider.Query(context.Background(), policy.Package{Ecosystem: "npm", Name: "shell-quote", Version: "1.9.0"})
	if err != nil {
		t.Fatal(err)
	}
	finding := result.Findings[0]
	if strings.Join(finding.Aliases, ",") != "CVE-2026-102422" {
		t.Fatalf("aliases = %v", finding.Aliases)
	}
	if got, want := strings.Join(finding.Affected, "; "), "<1.8.5; >=1.9.0, <1.11.0; >=2.0.0, <=2.0.3; >=3.0.0"; got != want {
		t.Fatalf("affected = %q, want %q", got, want)
	}
	if got, want := strings.Join(finding.Fixed, ","), "1.11.0"; got != want {
		t.Fatalf("fixed = %q, want %q", got, want)
	}
}

func TestAffectedRangesNormalizesPyPINames(t *testing.T) {
	affected, fixed := affectedRanges([]osvAffected{{
		Package: osvPackageRef{Ecosystem: "PyPI", Name: "Zope.Interface"},
		Ranges:  []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "5.0"}}}},
	}}, "PyPI", "zope-interface")
	if strings.Join(affected, ";") != "<5.0" || strings.Join(fixed, ",") != "5.0" {
		t.Fatalf("affected = %v fixed = %v", affected, fixed)
	}
}

func TestFixesAfterKeepsUnorderableVersions(t *testing.T) {
	if got := strings.Join(fixesAfter([]string{"1.7.3", "1.11.0", "2.0.0.post1"}, "1.9.0"), ","); got != "1.11.0,2.0.0.post1" {
		t.Fatalf("got %q", got)
	}
	if got := strings.Join(fixesAfter([]string{"1.7.3", "1.11.0"}, "1.9.0.dev1"), ","); got != "1.7.3,1.11.0" {
		t.Fatalf("got %q", got)
	}
}

func TestAffectedRangesTreatsLimitAsAnUpperBound(t *testing.T) {
	affected, fixed := affectedRanges([]osvAffected{{
		Package: osvPackageRef{Ecosystem: "npm", Name: "pkg"},
		Ranges:  []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "1.0.0"}, {Limit: "2.0.0"}}}},
	}}, "npm", "pkg")
	if strings.Join(affected, ";") != ">=1.0.0, <2.0.0" || len(fixed) != 0 {
		t.Fatalf("affected = %v fixed = %v", affected, fixed)
	}
}

func TestOSVProviderKeepsMavenFixesThatSemVerWouldOrderEarlier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"vulns":[{"id":"GHSA-m","affected":[{"package":{"ecosystem":"Maven","name":"g:a"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.0-sp1"}]}]}]}]}`)
	}))
	defer server.Close()
	provider := NewOSVProvider(server.URL, time.Second, time.Minute)
	result, err := provider.Query(context.Background(), policy.Package{Ecosystem: "maven", Name: "g:a", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(result.Findings[0].Fixed, ","); got != "1.0.0-sp1" {
		t.Fatalf("fixed = %q, want the Maven service-pack fix kept", got)
	}
}
