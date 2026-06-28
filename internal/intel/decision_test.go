package intel

import (
	"testing"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

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
