package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/server"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("package_firewall_failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		configPath := fs.String("config", "configs/package-firewall.example.yml", "path to package firewall YAML config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		policyEngine, err := loadPolicy(cfg)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return server.Run(ctx, cfg, policyEngine, providerFromConfig(cfg))
	case "version":
		fmt.Println("package-firewall dev")
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func loadPolicy(cfg config.Config) (*policy.Engine, error) {
	if len(cfg.Policy.Files) == 0 {
		return policy.New(policy.Config{})
	}
	return policy.Load(cfg.Policy.Files)
}

func providerFromConfig(cfg config.Config) intel.Provider {
	if !cfg.Intel.OSV.Enabled {
		return intel.NoopProvider{}
	}
	return intel.NewOSVProvider(cfg.Intel.OSV.APIURL, cfg.Intel.OSV.Timeout.Std(), cfg.Intel.OSV.CacheTTL.Std())
}
