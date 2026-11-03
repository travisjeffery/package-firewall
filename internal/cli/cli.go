// Package cli implements the tidewaiter command. The package-firewall and pfw
// binaries are aliases kept for one release after the rename.
package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/travisjeffery/tidewaiter/internal/config"
	"github.com/travisjeffery/tidewaiter/internal/policy"
)

// Main runs the command named by os.Args, or defaultCommand when there are no
// arguments. An empty defaultCommand prints usage instead.
func Main(defaultCommand string) {
	args := os.Args[1:]
	if len(args) == 0 && defaultCommand != "" {
		args = []string{defaultCommand}
	}
	if len(args) > 0 && args[0] == "serve" {
		if err := serve(args[1:]); err != nil {
			slog.Error("package_firewall_failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := Run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Run dispatches every subcommand except serve, which Main runs so that its
// failures are logged as structured events.
func Run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "version":
		fmt.Println("tidewaiter dev")
		return nil
	case "validate", "routes", "decide", "identify", "prewarm":
		return runTool(args)
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: tidewaiter serve|version|validate|routes|decide|identify|prewarm")
}

func loadPolicy(cfg config.Config) (*policy.Engine, error) {
	if len(cfg.Policy.Files) == 0 {
		return policy.New(policy.Config{})
	}
	return policy.Load(cfg.Policy.Files)
}
