package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/objectcache"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/proxy"
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
		cacheConfig, err := cacheFromConfig(ctx, cfg)
		if err != nil {
			return err
		}
		return server.Run(ctx, cfg, policyEngine, providerFromConfig(cfg), cacheConfig)
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

func cacheFromConfig(ctx context.Context, cfg config.Config) (proxy.CacheConfig, error) {
	switch cfg.Cache.Backend {
	case "", "none":
		return proxy.CacheConfig{}, nil
	case "filesystem":
		return proxy.CacheConfig{
			Store:                objectcache.NewFileSystemStore(cfg.Cache.Filesystem.Directory),
			ArtifactTTL:          cfg.Cache.ArtifactTTL.Std(),
			ArtifactStaleIfError: cfg.Cache.ArtifactStaleIfError.Std(),
			MaxObjectSize:        cfg.Cache.MaxObjectSize,
		}, nil
	case "s3_dynamodb":
		return s3DynamoDBCacheFromConfig(ctx, cfg)
	default:
		return proxy.CacheConfig{}, fmt.Errorf("unsupported cache backend %q", cfg.Cache.Backend)
	}
}

func s3DynamoDBCacheFromConfig(ctx context.Context, cfg config.Config) (proxy.CacheConfig, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return proxy.CacheConfig{}, err
	}
	store := objectcache.NewS3DynamoDBStore(objectcache.S3DynamoDBConfig{
		S3Client:  s3.NewFromConfig(awsCfg),
		DDBClient: dynamodb.NewFromConfig(awsCfg),
		Bucket:    cfg.Cache.S3.Bucket,
		Prefix:    cfg.Cache.S3.Prefix,
		Table:     cfg.Cache.DynamoDB.Table,
	})
	return proxy.CacheConfig{
		Store:                store,
		ArtifactTTL:          cfg.Cache.ArtifactTTL.Std(),
		ArtifactStaleIfError: cfg.Cache.ArtifactStaleIfError.Std(),
		MaxObjectSize:        cfg.Cache.MaxObjectSize,
	}, nil
}
