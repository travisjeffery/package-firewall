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
	"golang.org/x/mod/semver"
)

const (
	maxOSVResponseBytes = 4 << 20
	maxOSVFindings      = 1024
)

const defaultOSVCacheEntries = 4096

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
		cache:  cache.NewWithMaxEntries[Result](defaultOSVCacheEntries),
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
	decoded, err := decodeOSVResponse(resp.Body)
	if err != nil {
		return Result{}, err
	}
	result := Result{Findings: make([]Finding, 0, len(decoded.Vulns))}
	for _, vuln := range decoded.Vulns {
		affected, fixed := affectedRanges(vuln.Affected, ecosystem, name)
		if semverOrdered(ecosystem) {
			fixed = fixesAfter(fixed, pkg.Version)
		}
		result.Findings = append(result.Findings, Finding{
			ID:       vuln.ID,
			Aliases:  vuln.Aliases,
			Summary:  vuln.Summary,
			Severity: maxSeverity(vuln.Severity),
			Affected: affected,
			Fixed:    fixed,
		})
	}
	p.cache.Set(key, result, p.ttl)
	return result, nil
}

func decodeOSVResponse(body io.Reader) (osvResponse, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxOSVResponseBytes+1))
	if err != nil {
		return osvResponse{}, err
	}
	if len(raw) > maxOSVResponseBytes {
		return osvResponse{}, fmt.Errorf("osv response exceeds %d bytes", maxOSVResponseBytes)
	}
	var decoded osvResponse
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return osvResponse{}, err
	}
	if len(decoded.Vulns) > maxOSVFindings {
		return osvResponse{}, fmt.Errorf("osv response contains %d vulnerabilities, max %d", len(decoded.Vulns), maxOSVFindings)
	}
	return decoded, nil
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

// affectedRanges renders the advisory's ranges for the queried package. A record
// can cover several packages (a renamed module, a monorepo's siblings); when none
// matches by name, every range is used rather than reporting nothing.
func affectedRanges(entries []osvAffected, ecosystem, name string) ([]string, []string) {
	var matching []osvAffected
	for _, entry := range entries {
		if strings.EqualFold(entry.Package.Ecosystem, ecosystem) && normalizeOSVName(ecosystem, entry.Package.Name) == normalizeOSVName(ecosystem, name) {
			matching = append(matching, entry)
		}
	}
	if len(matching) == 0 {
		matching = entries
	}
	var affected, fixed []string
	seenFixed := map[string]bool{}
	for _, entry := range matching {
		for _, r := range entry.Ranges {
			if r.Type == "GIT" {
				continue
			}
			lower := ""
			for _, event := range r.Events {
				switch {
				case event.Introduced != "":
					lower = event.Introduced
				case event.Fixed != "":
					affected = append(affected, rangeText(lower, "<"+event.Fixed))
					if !seenFixed[event.Fixed] {
						seenFixed[event.Fixed] = true
						fixed = append(fixed, event.Fixed)
					}
					lower = ""
				case event.LastAffected != "":
					affected = append(affected, rangeText(lower, "<="+event.LastAffected))
					lower = ""
				case event.Limit != "":
					affected = append(affected, rangeText(lower, "<"+event.Limit))
					lower = ""
				}
			}
			if lower != "" {
				affected = append(affected, rangeText(lower, ""))
			}
		}
	}
	return affected, fixed
}

// semverOrdered reports whether the ecosystem orders versions by SemVer. Maven
// and PyPI versions often parse as SemVer but order differently (Maven puts
// 1.0.0-sp1 after 1.0.0), so their fixes are never filtered.
func semverOrdered(ecosystem string) bool {
	return ecosystem == "npm" || ecosystem == "Go"
}

// fixesAfter drops fix versions older than the requested one, so a 1.9.0 user
// is not told about the 1.7.3 fix on an older branch. Versions that do not
// parse as SemVer are kept.
func fixesAfter(fixed []string, version string) []string {
	current := semverOf(version)
	if current == "" {
		return fixed
	}
	kept := make([]string, 0, len(fixed))
	for _, candidate := range fixed {
		if v := semverOf(candidate); v == "" || semver.Compare(v, current) > 0 {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func semverOf(version string) string {
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !semver.IsValid(version) {
		return ""
	}
	return version
}

func rangeText(introduced, upper string) string {
	if introduced == "0" {
		introduced = ""
	}
	switch {
	case introduced == "" && upper == "":
		return "all versions"
	case introduced == "":
		return upper
	case upper == "":
		return ">=" + introduced
	default:
		return ">=" + introduced + ", " + upper
	}
}

func normalizeOSVName(ecosystem, name string) string {
	name = strings.ToLower(name)
	if ecosystem == "PyPI" {
		name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	}
	return name
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
	Aliases  []string      `json:"aliases"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Affected []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package osvPackageRef `json:"package"`
	Ranges  []osvRange    `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
