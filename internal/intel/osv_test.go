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

func TestOSVProviderIgnoresWithdrawnRecords(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"vulns":[
			{"id":"MAL-2026-1","withdrawn":"2026-01-02T00:00:00Z"},
			{"id":"GHSA-live","withdrawn":"2999-01-01T00:00:00Z"},
			{"id":"GHSA-kept"}]}`)
	}))
	defer server.Close()

	result, err := NewOSVProvider(server.URL, time.Second, time.Minute).Query(context.Background(), policy.Package{Ecosystem: "npm", Name: "pkg", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, finding := range result.Findings {
		ids = append(ids, finding.ID)
	}
	if strings.Join(ids, ",") != "GHSA-live,GHSA-kept" {
		t.Fatalf("findings = %v", ids)
	}
}

func TestOSVProviderKeepsAKnownMaliciousResultThroughAnOutage(t *testing.T) {
	var response string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if response == "" {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	provider := NewOSVProvider(server.URL, time.Second, time.Nanosecond)
	query := func(name string) (Result, error) {
		return provider.Query(context.Background(), policy.Package{Ecosystem: "npm", Name: name, Version: "1.0.0"})
	}

	response = `{"vulns":[{"id":"MAL-2026-1"}]}`
	if _, err := query("evil"); err != nil {
		t.Fatal(err)
	}
	response = `{"vulns":[{"id":"GHSA-ordinary"}]}`
	if _, err := query("ordinary"); err != nil {
		t.Fatal(err)
	}

	response = ""
	result, err := query("evil")
	if err != nil || len(result.Findings) != 1 || result.Findings[0].ID != "MAL-2026-1" {
		t.Fatalf("result = %+v, err = %v; want the retained MAL finding", result, err)
	}
	if _, err := query("ordinary"); err == nil {
		t.Fatal("an outage must still surface for packages with no malicious result")
	}

	response = `{"vulns":[]}`
	if _, err := query("evil"); err != nil {
		t.Fatal(err)
	}
	response = ""
	if _, err := query("evil"); err == nil {
		t.Fatal("a later clean answer must drop the retained malicious result")
	}
}

// The shape OSV returns for coa@2.0.3: GitHub malware with no severity and no
// MAL- alias, identified only by CWE-506.
func TestOSVProviderBlocksUnscoredGitHubMalware(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"vulns":[{"id":"GHSA-73qr-pfmq-6rp8","summary":"Embedded malware in coa",
			"database_specific":{"severity":"CRITICAL","github_reviewed":true,"cwe_ids":["CWE-506"]},
			"affected":[{"package":{"name":"coa","ecosystem":"npm"},"versions":["2.0.3","2.0.4","2.1.1","2.1.3","3.0.1","3.1.3"]}]}]}`)
	}))
	defer server.Close()

	result, err := NewOSVProvider(server.URL, time.Second, time.Minute).Query(context.Background(), policy.Package{Ecosystem: "npm", Name: "coa", Version: "2.0.3"})
	if err != nil {
		t.Fatal(err)
	}
	decision := Decide(result, policy.ActionWarn, 9.0)
	if decision.Action != policy.ActionBlock || decision.Kind != policy.KindMalware || decision.Reason != "malicious package GHSA-73qr-pfmq-6rp8" {
		t.Fatalf("decision = %+v", decision)
	}
}
