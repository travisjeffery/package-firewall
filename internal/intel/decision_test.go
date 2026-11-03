package intel

import (
	"testing"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

func TestDecideBlocksOnTheMostSevereFindingOverThreshold(t *testing.T) {
	decision := Decide(Result{Findings: []Finding{
		{ID: "GHSA-a", Severity: 9.1},
		{ID: "GHSA-b", Severity: 9.8, Aliases: []string{"CVE-1"}, Fixed: []string{"2.0.0"}},
		{ID: "GHSA-c", Severity: 4.0},
	}}, policy.ActionWarn, 9.0)
	if decision.Action != policy.ActionBlock || decision.Kind != policy.KindVulnerability {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Reason != "vulnerability GHSA-b severity 9.8 exceeds threshold 9.0" {
		t.Fatalf("reason = %q", decision.Reason)
	}
	a := decision.Advisory
	if a.ID != "GHSA-b" || a.Threshold != 9.0 || a.Fixed[0] != "2.0.0" || a.URL != "https://osv.dev/vulnerability/GHSA-b" {
		t.Fatalf("advisory = %+v", a)
	}
}

func TestDecideWarnsBelowThresholdWithTheWorstAdvisory(t *testing.T) {
	decision := Decide(Result{Findings: []Finding{{ID: "GHSA-a", Severity: 3}, {ID: "GHSA-b", Severity: 7}}}, "", 9.0)
	if decision.Action != policy.ActionWarn || decision.Reason != "vulnerability findings: GHSA-a,GHSA-b" || decision.Advisory.ID != "GHSA-b" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestDecideLabelsMaliciousPackages(t *testing.T) {
	decision := Decide(Result{Findings: []Finding{{ID: "MAL-2026-1", Severity: 10}}}, policy.ActionWarn, 9.0)
	if decision.Kind != policy.KindMalware {
		t.Fatalf("kind = %s", decision.Kind)
	}
}

func TestDecideBlocksAboveThreshold(t *testing.T) {
	decision := Decide(Result{Findings: []Finding{{ID: "OSV-1", Severity: 9.8}}}, policy.ActionWarn, 9.0)
	if decision.Action != policy.ActionBlock {
		t.Fatalf("action = %s", decision.Action)
	}
}

func TestDecideUsesDefaultActionBelowThreshold(t *testing.T) {
	decision := Decide(Result{Findings: []Finding{{ID: "OSV-1", Severity: 5.0}}}, policy.ActionWarn, 9.0)
	if decision.Action != policy.ActionWarn {
		t.Fatalf("action = %s", decision.Action)
	}
}
