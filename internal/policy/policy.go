package policy

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Action string

const (
	ActionAllow   Action = "allow"
	ActionWarn    Action = "warn"
	ActionBlock   Action = "block"
	ActionMonitor Action = "monitor"
	ActionUnknown Action = "unknown"
)

type Package struct {
	Ecosystem   string
	Name        string
	Version     string
	PURL        string
	PublishedAt time.Time
}

type Decision struct {
	Action      Action
	Reason      string
	MatchedRule string
}

type Config struct {
	Allow    []string       `yaml:"allow"`
	Warn     []string       `yaml:"warn"`
	Deny     []string       `yaml:"deny"`
	Cooldown CooldownConfig `yaml:"cooldown"`
}

type CooldownConfig struct {
	Enabled bool          `yaml:"enabled"`
	MinAge  time.Duration `yaml:"min_age"`
}

func (c *CooldownConfig) UnmarshalYAML(unmarshal func(any) error) error {
	type rawCooldownConfig struct {
		Enabled bool `yaml:"enabled"`
		MinAge  any  `yaml:"min_age"`
	}
	var raw rawCooldownConfig
	if err := unmarshal(&raw); err != nil {
		return err
	}
	c.Enabled = raw.Enabled
	switch value := raw.MinAge.(type) {
	case nil:
		return nil
	case int:
		c.MinAge = time.Duration(value)
	case string:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		c.MinAge = parsed
	default:
		return fmt.Errorf("unsupported cooldown.min_age type %T", value)
	}
	return nil
}

type engineRule struct {
	action  Action
	pattern string
	re      *regexp.Regexp
}

type Engine struct {
	rules    []engineRule
	cooldown CooldownConfig
}

func Load(files []string) (*Engine, error) {
	var merged Config
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var cfg Config
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		merged.Allow = append(merged.Allow, cfg.Allow...)
		merged.Warn = append(merged.Warn, cfg.Warn...)
		merged.Deny = append(merged.Deny, cfg.Deny...)
		if cfg.Cooldown.Enabled {
			merged.Cooldown = cfg.Cooldown
		}
	}
	return New(merged)
}

func New(cfg Config) (*Engine, error) {
	var errs []error
	var rules []engineRule
	add := func(action Action, patterns []string) {
		for _, pattern := range patterns {
			re, err := compileGlob(pattern)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s %q: %w", action, pattern, err))
				continue
			}
			rules = append(rules, engineRule{action: action, pattern: pattern, re: re})
		}
	}
	// Deny intentionally comes first. A broad allow cannot mask an explicit deny.
	add(ActionBlock, cfg.Deny)
	add(ActionAllow, cfg.Allow)
	add(ActionWarn, cfg.Warn)
	if cfg.Cooldown.MinAge == 0 {
		cfg.Cooldown.MinAge = 24 * time.Hour
	}
	return &Engine{rules: rules, cooldown: cfg.Cooldown}, errors.Join(errs...)
}

func (e *Engine) Evaluate(pkg Package) Decision {
	if pkg.PURL == "" {
		return Decision{Action: ActionUnknown, Reason: "package version could not be identified"}
	}
	for _, rule := range e.rules {
		if rule.re.MatchString(pkg.PURL) {
			return Decision{Action: rule.action, Reason: fmt.Sprintf("matched %s policy", rule.action), MatchedRule: rule.pattern}
		}
	}
	if e.cooldown.Enabled && !pkg.PublishedAt.IsZero() && time.Since(pkg.PublishedAt) < e.cooldown.MinAge {
		return Decision{Action: ActionBlock, Reason: "package is newer than cooldown policy"}
	}
	return Decision{Action: ActionAllow, Reason: "no policy rule matched"}
}

func compileGlob(pattern string) (*regexp.Regexp, error) {
	if strings.TrimSpace(pattern) == "" {
		return nil, errors.New("empty pattern")
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
