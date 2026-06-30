package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
	"github.com/travisjeffery/package-firewall/internal/cache"
	"github.com/travisjeffery/package-firewall/internal/policy"
)

type OSVProvider struct {
	apiURL string
	client *http.Client
	cache  *cache.Cache[Result]
	ttl    time.Duration
}

func NewOSVProvider(apiURL string, timeout time.Duration, ttl time.Duration) *OSVProvider {
	return &OSVProvider{
		apiURL: apiURL,
		client: &http.Client{Timeout: timeout},
		cache:  cache.New[Result](),
		ttl:    ttl,
	}
}

func (p *OSVProvider) Query(ctx context.Context, pkg policy.Package) (Result, error) {
	ecosystem, name := osvPackage(pkg)
	if ecosystem == "" || name == "" || pkg.Version == "" {
		return Result{}, nil
	}
	key := ecosystem + "|" + name + "|" + pkg.Version
	if cached, ok := p.cache.Get(key); ok {
		return cached, nil
	}
	body, err := json.Marshal(osvQuery{
		Version: pkg.Version,
		Package: osvPackageRef{
			Name:      name,
			Ecosystem: ecosystem,
		},
	})
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiURL, bytes.NewReader(body))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return Result{}, fmt.Errorf("osv returned %d: %s", resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	var decoded osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return Result{}, err
	}
	result := Result{Findings: make([]Finding, 0, len(decoded.Vulns))}
	for _, vuln := range decoded.Vulns {
		result.Findings = append(result.Findings, Finding{
			ID:       vuln.ID,
			Summary:  vuln.Summary,
			Severity: maxSeverity(vuln.Severity),
		})
	}
	p.cache.Set(key, result, p.ttl)
	return result, nil
}

func osvPackage(pkg policy.Package) (string, string) {
	switch pkg.Ecosystem {
	case "npm":
		return "npm", pkg.Name
	case "pypi":
		return "PyPI", pkg.Name
	case "maven":
		return "Maven", pkg.Name
	case "go":
		return "Go", pkg.Name
	default:
		return "", ""
	}
}

func maxSeverity(items []osvSeverity) float64 {
	var max float64
	for _, item := range items {
		if score := severityScore(item.Score); score > max {
			max = score
		}
	}
	return max
}

// severityScore resolves an OSV severity entry to a numeric CVSS base score.
//
// OSV reports severity as a CVSS *vector string* (e.g.
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"), not a bare number, so the
// base score must be computed from the vector. We also accept an already-numeric
// score for providers that report one. Anything we cannot parse yields 0 so the
// caller falls back to the configured default action rather than mis-blocking.
func severityScore(raw string) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
		return parsed
	}
	switch {
	case strings.HasPrefix(raw, "CVSS:3.0"):
		if c, err := gocvss30.ParseVector(raw); err == nil {
			return c.BaseScore()
		}
	case strings.HasPrefix(raw, "CVSS:3.1"):
		if c, err := gocvss31.ParseVector(raw); err == nil {
			return c.BaseScore()
		}
	case strings.HasPrefix(raw, "CVSS:4.0"):
		if c, err := gocvss40.ParseVector(raw); err == nil {
			return c.Score()
		}
	default:
		// CVSS v2 vectors carry no "CVSS:" version prefix.
		if c, err := gocvss20.ParseVector(raw); err == nil {
			return c.BaseScore()
		}
	}
	return 0
}

type osvQuery struct {
	Version string        `json:"version,omitempty"`
	Package osvPackageRef `json:"package"`
}

type osvPackageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
