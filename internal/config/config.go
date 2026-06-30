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

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
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
	Name             string   `yaml:"name"`
	Ecosystem        string   `yaml:"ecosystem"`
	PathPrefix       string   `yaml:"path_prefix"`
	UpstreamURL      string   `yaml:"upstream_url"`
	FileUpstreamURL  string   `yaml:"file_upstream_url"`
	UpstreamTokenEnv string   `yaml:"upstream_token_env"`
	CacheTTL         Duration `yaml:"cache_ttl"`
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
			{Name: "npm", Ecosystem: "npm", PathPrefix: "/npm/", UpstreamURL: "https://registry.npmjs.org/", CacheTTL: Duration(10 * time.Minute)},
			{Name: "pypi", Ecosystem: "pypi", PathPrefix: "/pypi/", UpstreamURL: "https://pypi.org/", FileUpstreamURL: "https://files.pythonhosted.org/", CacheTTL: Duration(10 * time.Minute)},
			{Name: "maven", Ecosystem: "maven", PathPrefix: "/maven/", UpstreamURL: "https://repo1.maven.org/maven2/", CacheTTL: Duration(10 * time.Minute)},
			{Name: "go", Ecosystem: "go", PathPrefix: "/go/", UpstreamURL: "https://proxy.golang.org/", CacheTTL: Duration(10 * time.Minute)},
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
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
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
	if cfg.Decision.DefaultVulnerabilityAction != "warn" && cfg.Decision.DefaultVulnerabilityAction != "block" && cfg.Decision.DefaultVulnerabilityAction != "monitor" {
		errs = append(errs, errors.New("decision.default_vulnerability_action must be warn, block, or monitor"))
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
