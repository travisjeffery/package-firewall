package policy

import "testing"

func TestEvaluateDenyWinsOverAllow(t *testing.T) {
	engine, err := New(Config{
		Deny:  []string{"pkg:npm/lodash@4.*"},
		Allow: []string{"pkg:npm/lodash@*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(Package{PURL: "pkg:npm/lodash@4.17.21"})
	if decision.Action != ActionBlock {
		t.Fatalf("action = %s", decision.Action)
	}
}

func TestEvaluateWarnRule(t *testing.T) {
	engine, err := New(Config{Warn: []string{"pkg:pypi/django@5.*"}})
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(Package{PURL: "pkg:pypi/django@5.0.6"})
	if decision.Action != ActionWarn {
		t.Fatalf("action = %s", decision.Action)
	}
}
