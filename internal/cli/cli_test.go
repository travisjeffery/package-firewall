package cli

import (
	"strings"
	"testing"
)

func TestRunDispatchesToolCommands(t *testing.T) {
	if err := Run([]string{"validate", "--config", "../../configs/package-firewall.example.yml"}); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestRunRejectsUnknownAndMissingCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}} {
		err := Run(args)
		if err == nil || !strings.Contains(err.Error(), "usage: tidewaiter") {
			t.Fatalf("Run(%q) = %v, want usage error", args, err)
		}
	}
}
