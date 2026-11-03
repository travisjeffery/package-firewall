package explain

import (
	"strings"
	"testing"
	"time"

	"github.com/travisjeffery/tidewaiter/internal/policy"
)

var shellQuote = policy.Package{Ecosystem: "npm", Name: "shell-quote", Version: "1.9.0", PURL: "pkg:npm/shell-quote@1.9.0"}

func TestMessages(t *testing.T) {
	allowedAfter := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	vuln := &policy.Advisory{
		ID:        "GHSA-pqg4-j6r4-53mv",
		Aliases:   []string{"CVE-2026-102422"},
		Summary:   "quote() command injection\n",
		Severity:  9.2,
		Threshold: 9.0,
		Affected:  []string{"<1.11.0"},
		Fixed:     []string{"1.11.0"},
		URL:       "https://osv.dev/vulnerability/GHSA-pqg4-j6r4-53mv",
	}
	tests := []struct {
		name     string
		pkg      policy.Package
		decision policy.Decision
		want     string
	}{
		{
			name:     "vulnerability with a fix",
			pkg:      shellQuote,
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindVulnerability, Advisory: vuln},
			want:     "Blocked by Tidewaiter: shell-quote@1.9.0 has GHSA-pqg4-j6r4-53mv (CVE-2026-102422), severity 9.2 >= threshold 9.0: quote() command injection. Affected: <1.11.0. Fixed in 1.11.0; upgrade to a fixed version (update the lockfile, or override the transitive dependency). Details: https://osv.dev/vulnerability/GHSA-pqg4-j6r4-53mv. Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name: "vulnerability without a fix",
			pkg:  shellQuote,
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindVulnerability, Advisory: &policy.Advisory{
				ID: "GHSA-xxxx", Severity: 9.8, Threshold: 9.0, Affected: []string{">=1.0.0"},
			}},
			want: "Blocked by Tidewaiter: shell-quote@1.9.0 has GHSA-xxxx, severity 9.8 >= threshold 9.0. Affected: >=1.0.0. No fixed version is published; remove or replace the dependency, or request an exception. Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name:     "malware",
			pkg:      shellQuote,
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindMalware, Advisory: &policy.Advisory{ID: "MAL-2026-1", Summary: "Malicious code in shell-quote (npm)", Severity: 10, Threshold: 9}},
			want:     "Blocked by Tidewaiter: shell-quote@1.9.0 is a known malicious package (MAL-2026-1): Malicious code in shell-quote (npm). Remove the dependency and treat any machine that installed it as compromised. Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name:     "deny rule",
			pkg:      shellQuote,
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindPolicyRule, MatchedRule: "pkg:npm/shell-quote@*", Reason: "matched block policy"},
			want:     "Blocked by Tidewaiter: shell-quote@1.9.0 matches deny rule pkg:npm/shell-quote@*. Use a different package or version, or request an exception. Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name:     "cooldown",
			pkg:      shellQuote,
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindCooldown, AllowedAfter: allowedAfter},
			want:     "Blocked by Tidewaiter: shell-quote@1.9.0 was published too recently for the release cooldown; it is allowed after 2026-10-07T12:00:00Z. Pin an earlier version until then. Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name:     "unknown package",
			pkg:      policy.Package{Ecosystem: "pypi"},
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindUnknownPackage},
			want:     "Blocked by Tidewaiter: the package and version could not be identified from the request path. Check the request URL; request an exception if it is a legitimate artifact. Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name:     "intel error",
			pkg:      shellQuote,
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindIntelError},
			want:     "Blocked by Tidewaiter: the vulnerability lookup for shell-quote@1.9.0 failed. Retry the install; the lookup fails closed while the vulnerability service is unavailable. Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name: "warning below threshold",
			pkg:  shellQuote,
			decision: policy.Decision{Action: policy.ActionWarn, Kind: policy.KindVulnerability, Advisory: &policy.Advisory{
				ID: "GHSA-low", Severity: 5.3, Threshold: 9.0, URL: "https://osv.dev/vulnerability/GHSA-low",
			}},
			want: "Tidewaiter allows shell-quote@1.9.0 (action warn): shell-quote@1.9.0 has GHSA-low, severity 5.3 below threshold 9.0. Details: https://osv.dev/vulnerability/GHSA-low. Request ID: req-1.",
		},
		{
			name: "default action blocks below the threshold",
			pkg:  shellQuote,
			decision: policy.Decision{Action: policy.ActionBlock, Kind: policy.KindVulnerability, Advisory: &policy.Advisory{
				ID: "GHSA-low", Severity: 5.3, Threshold: 9.0, Fixed: []string{"1.9.1"},
			}},
			want: "Blocked by Tidewaiter: shell-quote@1.9.0 has GHSA-low, severity 5.3; the severity threshold does not block it, but the default vulnerability action does. Fixed in 1.9.1; upgrade to a fixed version (update the lockfile, or override the transitive dependency). Request ID: req-1. Exceptions: https://example.test/exceptions",
		},
		{
			name:     "allowed",
			pkg:      shellQuote,
			decision: policy.Decision{Action: policy.ActionAllow, Reason: "policy and intel allowed package"},
			want:     "Tidewaiter allows shell-quote@1.9.0: policy and intel allowed package.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.pkg, tt.decision, "req-1", "https://example.test/exceptions")
			if got.Message != tt.want {
				t.Fatalf("message:\n got %s\nwant %s", got.Message, tt.want)
			}
			if got.Blocked != (tt.decision.Action == policy.ActionBlock) {
				t.Fatalf("blocked = %v for action %s", got.Blocked, tt.decision.Action)
			}
		})
	}
}

func TestHeaderValueIsOneASCIILine(t *testing.T) {
	got := HeaderValue("a\nb  ≥ c\td", 100)
	if got != "a b ? c d" {
		t.Fatalf("got %q", got)
	}
	long := HeaderValue(strings.Repeat("x", 50), 10)
	if long != "xxxxxxx..." {
		t.Fatalf("got %q", long)
	}
}
