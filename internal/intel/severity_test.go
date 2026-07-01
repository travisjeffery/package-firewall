package intel

import (
	"math"
	"testing"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

// Regression for the severity-parsing bug: OSV reports CVSS *vector strings*, but
// the old maxSeverity ran ParseFloat on the trailing vector component (e.g.
// "A:H"), always yielding 0. Every vulnerability then scored 0, so the
// block-threshold path never fired and critical packages were served.

func TestSeverityScoreParsesCVSSVectors(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
	}{
		// Real vectors OSV returns for lodash 4.17.11.
		{"v3.1 CVE-2019-10744", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H", 9.1},
		{"v3.1 high", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1},
		{"v3.0 critical", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
	}
	for _, tc := range cases {
		got := severityScore(tc.vector)
		if math.Abs(got-tc.want) > 0.1 {
			t.Errorf("%s: severityScore(%q) = %v, want ~%v", tc.name, tc.vector, got, tc.want)
		}
	}
}

func TestSeverityScoreNumericAndUnparseable(t *testing.T) {
	if got := severityScore("9.8"); got != 9.8 {
		t.Errorf("numeric score: got %v, want 9.8", got)
	}
	if got := severityScore(""); got != 0 {
		t.Errorf("empty: got %v, want 0", got)
	}
	if got := severityScore("CVSS:3.1/garbage"); got != 0 {
		t.Errorf("unparseable vector must yield 0 (fail safe), got %v", got)
	}
}

func TestMaxSeverityTakesMaxAcrossFindings(t *testing.T) {
	items := []osvSeverity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}, // ~7.x
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}, // 9.1
	}
	if got := maxSeverity(items); got < 9.0 {
		t.Errorf("maxSeverity = %v, want >= 9.0 (the critical finding must win)", got)
	}
}

// End-to-end of the fix: a CVSS >= threshold finding must BLOCK even when the
// default action is warn. Before the fix the severity resolved to 0, so this
// returned warn and the package was served.
func TestCriticalVectorBlocksUnderWarnDefault(t *testing.T) {
	sev := maxSeverity([]osvSeverity{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"},
	})
	d := Decide(Result{Findings: []Finding{{ID: "CVE-2019-10744", Severity: sev}}}, policy.ActionWarn, 9.0)
	if d.Action != policy.ActionBlock {
		t.Fatalf("severity %v >= 9.0 must block under warn default; got %q (%s)", sev, d.Action, d.Reason)
	}
}
