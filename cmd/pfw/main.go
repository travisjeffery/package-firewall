package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		configPath := fs.String("config", "configs/package-firewall.example.yml", "path to config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		_, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		fmt.Println("config ok")
		return nil
	case "routes":
		fs := flag.NewFlagSet("routes", flag.ExitOnError)
		configPath := fs.String("config", "configs/package-firewall.example.yml", "path to config")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tECOSYSTEM\tPREFIX\tUPSTREAM")
		for _, route := range cfg.Routes {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", route.Name, route.Ecosystem, route.PathPrefix, route.UpstreamURL)
		}
		return w.Flush()
	case "decide":
		fs := flag.NewFlagSet("decide", flag.ExitOnError)
		configPath := fs.String("config", "configs/package-firewall.example.yml", "path to config")
		ecosystem := fs.String("ecosystem", "", "ecosystem: npm, pypi, maven, go")
		name := fs.String("name", "", "package name")
		version := fs.String("version", "", "package version")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		engine, err := loadPolicy(cfg)
		if err != nil {
			return err
		}
		pkg := packageFromInput(*ecosystem, *name, *version)
		decision := engine.Evaluate(pkg)
		if decision.Action == policy.ActionAllow && decision.MatchedRule == "" && cfg.Intel.OSV.Enabled {
			result, err := intel.NewOSVProvider(cfg.Intel.OSV.APIURL, cfg.Intel.OSV.Timeout.Std(), cfg.Intel.OSV.CacheTTL.Std()).Query(context.Background(), pkg)
			if err == nil {
				decision = intel.Decide(result, policy.Action(cfg.Decision.DefaultVulnerabilityAction), cfg.Decision.VulnerabilityBlockThreshold)
			}
		}
		fmt.Printf("%s\t%s\t%s\n", decision.Action, pkg.PURL, decision.Reason)
		return nil
	case "identify":
		fs := flag.NewFlagSet("identify", flag.ExitOnError)
		ecosystem := fs.String("ecosystem", "", "ecosystem")
		prefix := fs.String("prefix", "/", "route prefix")
		path := fs.String("path", "", "request path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		info := registry.Identify(registry.Route{Ecosystem: *ecosystem, PathPrefix: *prefix}, *path)
		fmt.Printf("%s\t%s\t%s\t%v\n", info.Kind, info.Package.PURL, info.UpstreamPath, info.NeedsDecision)
		return nil
	default:
		return usage()
	}
}

func usage() error {
	return fmt.Errorf("usage: pfw validate|routes|decide|identify")
}

func loadPolicy(cfg config.Config) (*policy.Engine, error) {
	if len(cfg.Policy.Files) == 0 {
		return policy.New(policy.Config{})
	}
	return policy.Load(cfg.Policy.Files)
}

func packageFromInput(ecosystem, name, version string) policy.Package {
	pkg := policy.Package{Ecosystem: ecosystem, Name: name, Version: version}
	switch ecosystem {
	case "npm":
		pkg.PURL = "pkg:npm/" + name + "@" + version
	case "pypi":
		pkg.PURL = "pkg:pypi/" + name + "@" + version
	case "maven":
		pkg.PURL = "pkg:maven/" + name + "@" + version
	case "go":
		pkg.PURL = "pkg:golang/" + name + "@" + version
	}
	return pkg
}
