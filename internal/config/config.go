package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const maxS3PutObjectSize = int64(5_000_000_000)

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
	Cache    CacheConfig    `yaml:"cache"`
	Decision DecisionConfig `yaml:"decision"`
	Intel    IntelConfig    `yaml:"intel"`
	Policy   PolicyConfig   `yaml:"policy"`
	Routes   []RouteConfig  `yaml:"routes"`
}

type ServerConfig struct {
	ListenAddr      string   `yaml:"listen_addr"`
	ReadTimeout     Duration `yaml:"read_timeout"`
	WriteTimeout    Duration `yaml:"write_timeout"`
	ShutdownTimeout Duration `yaml:"shutdown_timeout"`
	PublicBaseURL   string   `yaml:"public_base_url"`
}

type AuthConfig struct {
	BearerTokenEnv   string `yaml:"bearer_token_env"`
	BasicUsernameEnv string `yaml:"basic_username_env"`
	BasicPasswordEnv string `yaml:"basic_password_env"`
}

type CacheConfig struct {
	Backend       string                `yaml:"backend"`
	ArtifactTTL   Duration              `yaml:"artifact_ttl"`
	MaxObjectSize int64                 `yaml:"max_object_size"`
	TempDirectory string                `yaml:"temp_directory"`
	Filesystem    FilesystemCacheConfig `yaml:"filesystem"`
	S3            S3CacheConfig         `yaml:"s3"`
}

type FilesystemCacheConfig struct {
	Directory string `yaml:"directory"`
}

type S3CacheConfig struct {
	Bucket              string `yaml:"bucket"`
	Prefix              string `yaml:"prefix"`
	ExpectedBucketOwner string `yaml:"expected_bucket_owner"`
}

type DecisionConfig struct {
	FailOpenIntelErrors         bool    `yaml:"fail_open_intel_errors"`
	FailOpenUnknownPackage      bool    `yaml:"fail_open_unknown_package"`
	VulnerabilityBlockThreshold float64 `yaml:"vulnerability_block_threshold"`
	DefaultVulnerabilityAction  string  `yaml:"default_vulnerability_action"`
}

type IntelConfig struct {
	OSV OSVConfig `yaml:"osv"`
}

type OSVConfig struct {
	Enabled  bool     `yaml:"enabled"`
	APIURL   string   `yaml:"api_url"`
	Timeout  Duration `yaml:"timeout"`
	CacheTTL Duration `yaml:"cache_ttl"`
}

type PolicyConfig struct {
	Files []string `yaml:"files"`
}

type RouteConfig struct {
	Name             string `yaml:"name"`
	Ecosystem        string `yaml:"ecosystem"`
	PathPrefix       string `yaml:"path_prefix"`
	UpstreamURL      string `yaml:"upstream_url"`
	FileUpstreamURL  string `yaml:"file_upstream_url"`
	UpstreamTokenEnv string `yaml:"upstream_token_env"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			ListenAddr:      ":8080",
			ReadTimeout:     Duration(30 * time.Second),
			WriteTimeout:    Duration(10 * time.Minute),
			ShutdownTimeout: Duration(10 * time.Second),
			PublicBaseURL:   "http://localhost:8080",
		},
		Cache: CacheConfig{
			Backend:       "none",
			ArtifactTTL:   Duration(24 * time.Hour),
			MaxObjectSize: 512 << 20,
		},
		Decision: DecisionConfig{
			FailOpenIntelErrors:         true,
			FailOpenUnknownPackage:      true,
			VulnerabilityBlockThreshold: 9.0,
			DefaultVulnerabilityAction:  "warn",
		},
		Intel: IntelConfig{
			OSV: OSVConfig{
				Enabled:  true,
				APIURL:   "https://api.osv.dev/v1/query",
				Timeout:  Duration(8 * time.Second),
				CacheTTL: Duration(6 * time.Hour),
			},
		},
		Routes: []RouteConfig{
			{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: "https://registry.npmjs.org/"},
			{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: "https://pypi.org/", FileUpstreamURL: "https://files.pythonhosted.org/"},
			{Name: "maven", Ecosystem: "maven", PathPrefix: "/maven/", UpstreamURL: "https://repo1.maven.org/maven2/"},
			{Name: "go", Ecosystem: "go", PathPrefix: "/go/", UpstreamURL: "https://proxy.golang.org/"},
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Config{}, err
		}
		if len(cfg.Policy.Files) > 0 {
			base := filepath.Dir(path)
			for i, file := range cfg.Policy.Files {
				if !filepath.IsAbs(file) {
					cfg.Policy.Files[i] = filepath.Clean(filepath.Join(base, file))
				}
			}
		}
	}
	if err := applyEnv(&cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) error {
	if v := os.Getenv("PFW_LISTEN_ADDR"); v != "" {
		cfg.Server.ListenAddr = v
	}
	if v := os.Getenv("PFW_PUBLIC_BASE_URL"); v != "" {
		cfg.Server.PublicBaseURL = v
	}
	if v := os.Getenv("PFW_FAIL_OPEN_INTEL_ERRORS"); v != "" {
		cfg.Decision.FailOpenIntelErrors = parseBool(v, cfg.Decision.FailOpenIntelErrors)
	}
	if v := os.Getenv("PFW_FAIL_OPEN_UNKNOWN_PACKAGE"); v != "" {
		cfg.Decision.FailOpenUnknownPackage = parseBool(v, cfg.Decision.FailOpenUnknownPackage)
	}
	if v := os.Getenv("PFW_OSV_ENABLED"); v != "" {
		cfg.Intel.OSV.Enabled = parseBool(v, cfg.Intel.OSV.Enabled)
	}
	if v := os.Getenv("PFW_OSV_API_URL"); v != "" {
		cfg.Intel.OSV.APIURL = v
	}
	if v := os.Getenv("PFW_CACHE_BACKEND"); v != "" {
		cfg.Cache.Backend = v
	}
	if v := os.Getenv("PFW_CACHE_ARTIFACT_TTL"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("PFW_CACHE_ARTIFACT_TTL is invalid: %w", err)
		}
		cfg.Cache.ArtifactTTL = Duration(parsed)
	}
	if v := os.Getenv("PFW_CACHE_MAX_OBJECT_SIZE"); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("PFW_CACHE_MAX_OBJECT_SIZE is invalid: %w", err)
		}
		cfg.Cache.MaxObjectSize = parsed
	}
	if v := os.Getenv("PFW_CACHE_TEMP_DIRECTORY"); v != "" {
		cfg.Cache.TempDirectory = v
	}
	if v := os.Getenv("PFW_CACHE_FILESYSTEM_DIRECTORY"); v != "" {
		cfg.Cache.Filesystem.Directory = v
	}
	if v := os.Getenv("PFW_CACHE_S3_BUCKET"); v != "" {
		cfg.Cache.S3.Bucket = v
	}
	if v := os.Getenv("PFW_CACHE_S3_PREFIX"); v != "" {
		cfg.Cache.S3.Prefix = v
	}
	if v := os.Getenv("PFW_CACHE_S3_EXPECTED_BUCKET_OWNER"); v != "" {
		cfg.Cache.S3.ExpectedBucketOwner = v
	}
	return nil
}

func parseBool(value string, fallback bool) bool {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func (cfg Config) Validate() error {
	var errs []error
	if strings.TrimSpace(cfg.Server.ListenAddr) == "" {
		errs = append(errs, errors.New("server.listen_addr is required"))
	}
	if cfg.Server.WriteTimeout <= 0 {
		errs = append(errs, errors.New("server.write_timeout must be positive"))
	}
	if _, err := url.ParseRequestURI(cfg.Server.PublicBaseURL); err != nil {
		errs = append(errs, fmt.Errorf("server.public_base_url is invalid: %w", err))
	}
	switch cfg.Cache.Backend {
	case "", "none":
	case "filesystem":
		errs = append(errs, validateEnabledCache(cfg.Cache)...)
		if strings.TrimSpace(cfg.Cache.Filesystem.Directory) == "" {
			errs = append(errs, errors.New("cache.filesystem.directory is required when cache.backend=filesystem"))
		}
	case "s3":
		errs = append(errs, validateEnabledCache(cfg.Cache)...)
		if strings.TrimSpace(cfg.Cache.S3.Bucket) == "" {
			errs = append(errs, errors.New("cache.s3.bucket is required when cache.backend=s3"))
		}
		if cfg.Cache.MaxObjectSize > maxS3PutObjectSize {
			errs = append(errs, errors.New("cache.max_object_size cannot exceed 5 GB when cache.backend=s3"))
		}
		if owner := cfg.Cache.S3.ExpectedBucketOwner; owner != "" && !validAWSAccountID(owner) {
			errs = append(errs, errors.New("cache.s3.expected_bucket_owner must be a 12-digit AWS account ID"))
		}
	default:
		errs = append(errs, fmt.Errorf("cache.backend %q is unsupported", cfg.Cache.Backend))
	}
	if cfg.Decision.DefaultVulnerabilityAction != "warn" && cfg.Decision.DefaultVulnerabilityAction != "block" && cfg.Decision.DefaultVulnerabilityAction != "monitor" {
		errs = append(errs, errors.New("decision.default_vulnerability_action must be warn, block, or monitor"))
	}
	if cfg.Auth.BearerTokenEnv != "" {
		if value, ok := os.LookupEnv(cfg.Auth.BearerTokenEnv); !ok || value == "" {
			errs = append(errs, fmt.Errorf("auth.bearer_token_env %q is not set or is empty", cfg.Auth.BearerTokenEnv))
		}
	}
	if (cfg.Auth.BasicUsernameEnv == "") != (cfg.Auth.BasicPasswordEnv == "") {
		errs = append(errs, errors.New("auth.basic_username_env and auth.basic_password_env must be set together"))
	}
	if cfg.Auth.BasicUsernameEnv != "" {
		if value, ok := os.LookupEnv(cfg.Auth.BasicUsernameEnv); !ok || value == "" {
			errs = append(errs, fmt.Errorf("auth.basic_username_env %q is not set or is empty", cfg.Auth.BasicUsernameEnv))
		}
		if value, ok := os.LookupEnv(cfg.Auth.BasicPasswordEnv); !ok || value == "" {
			errs = append(errs, fmt.Errorf("auth.basic_password_env %q is not set or is empty", cfg.Auth.BasicPasswordEnv))
		}
	}
	if cfg.Intel.OSV.Enabled {
		if _, err := url.ParseRequestURI(cfg.Intel.OSV.APIURL); err != nil {
			errs = append(errs, fmt.Errorf("intel.osv.api_url is invalid: %w", err))
		}
		if cfg.Intel.OSV.Timeout <= 0 {
			errs = append(errs, errors.New("intel.osv.timeout must be positive"))
		}
		if cfg.Intel.OSV.CacheTTL <= 0 {
			errs = append(errs, errors.New("intel.osv.cache_ttl must be positive"))
		}
	}
	if len(cfg.Routes) == 0 {
		errs = append(errs, errors.New("at least one route is required"))
	}
	seen := map[string]bool{}
	for _, route := range cfg.Routes {
		if route.Name == "" {
			errs = append(errs, errors.New("route.name is required"))
		}
		if seen[route.PathPrefix] {
			errs = append(errs, fmt.Errorf("duplicate route path_prefix %q", route.PathPrefix))
		}
		seen[route.PathPrefix] = true
		if !strings.HasPrefix(route.PathPrefix, "/") || !strings.HasSuffix(route.PathPrefix, "/") {
			errs = append(errs, fmt.Errorf("route %q path_prefix must start and end with /", route.Name))
		}
		if _, err := url.ParseRequestURI(route.UpstreamURL); err != nil {
			errs = append(errs, fmt.Errorf("route %q upstream_url is invalid: %w", route.Name, err))
		}
		switch route.Ecosystem {
		case "npm", "pypi", "maven", "go":
		default:
			errs = append(errs, fmt.Errorf("route %q ecosystem %q is unsupported", route.Name, route.Ecosystem))
		}
	}
	return errors.Join(errs...)
}

func validateEnabledCache(cfg CacheConfig) []error {
	var errs []error
	if cfg.ArtifactTTL <= 0 {
		errs = append(errs, errors.New("cache.artifact_ttl must be positive"))
	}
	if cfg.MaxObjectSize <= 0 {
		errs = append(errs, errors.New("cache.max_object_size must be positive"))
	}
	return errs
}

func validAWSAccountID(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}
