package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/travisjeffery/tidewaiter/internal/artifactcache"
	"github.com/travisjeffery/tidewaiter/internal/config"
	"github.com/travisjeffery/tidewaiter/internal/coordination"
	"github.com/travisjeffery/tidewaiter/internal/intel"
	"github.com/travisjeffery/tidewaiter/internal/proxy"
	"github.com/travisjeffery/tidewaiter/internal/server"
)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "configs/package-firewall.example.yml", "path to Tidewaiter YAML config")
	if err := fs.Parse(args); err != nil {
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
	runtimeConfig, err := runtimeFromConfig(ctx, cfg)
	if err != nil {
		return err
	}
	return server.Run(ctx, cfg, policyEngine, providerFromConfig(cfg), runtimeConfig)
}

func providerFromConfig(cfg config.Config) intel.Provider {
	if !cfg.Intel.OSV.Enabled {
		return intel.NoopProvider{}
	}
	return intel.NewOSVProvider(cfg.Intel.OSV.APIURL, cfg.Intel.OSV.Timeout.Std(), cfg.Intel.OSV.CacheTTL.Std())
}

func runtimeFromConfig(ctx context.Context, cfg config.Config) (server.RuntimeConfig, error) {
	runtimeConfig := server.RuntimeConfig{Cache: proxy.CacheConfig{
		ArtifactTTL:   cfg.Cache.ArtifactTTL.Std(),
		MaxObjectSize: cfg.Cache.MaxObjectSize,
		TempDirectory: cfg.Cache.TempDirectory,
		ReadTimeout:   cfg.Cache.ReadTimeout.Std(),
		StoreTimeout:  cfg.Cache.StoreTimeout.Std(),
	}}
	var awsConfig aws.Config
	if cfg.Cache.Backend == "s3" || cfg.Coordination.Backend == "dynamodb" {
		loaded, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return server.RuntimeConfig{}, fmt.Errorf("load AWS configuration: %w", err)
		}
		awsConfig = loaded
	}
	switch cfg.Cache.Backend {
	case "", "none":
	case "filesystem":
		runtimeConfig.Cache.Store = artifactcache.NewFileSystemStore(cfg.Cache.Filesystem.Directory)
	case "s3":
		runtimeConfig.Cache.Store = artifactcache.NewS3Store(artifactcache.S3Config{
			Client:              s3.NewFromConfig(awsConfig),
			Bucket:              cfg.Cache.S3.Bucket,
			Prefix:              cfg.Cache.S3.Prefix,
			ExpectedBucketOwner: cfg.Cache.S3.ExpectedBucketOwner,
		})
	default:
		return server.RuntimeConfig{}, fmt.Errorf("unsupported cache backend %q", cfg.Cache.Backend)
	}
	if cfg.Coordination.Backend == "dynamodb" {
		coordinator, err := coordination.NewDynamoDB(coordination.DynamoDBConfig{
			Client:    dynamodb.NewFromConfig(awsConfig),
			Table:     cfg.Coordination.DynamoDB.Table,
			KeyPrefix: cfg.Coordination.DynamoDB.KeyPrefix,
		})
		if err != nil {
			return server.RuntimeConfig{}, err
		}
		runtimeConfig.Coordinator = coordinator
	}
	return runtimeConfig, nil
}
