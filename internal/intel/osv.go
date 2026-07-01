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

	"github.com/travisjeffery/package-firewall/internal/cache"
	"github.com/travisjeffery/package-firewall/internal/policy"
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
		result.Findings = append(result.Findings, Finding{
			ID:       vuln.ID,
			Summary:  vuln.Summary,
			Severity: maxSeverity(vuln.Severity),
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

func maxSeverity(items []osvSeverity) float64 {
	var max float64
	for _, item := range items {
		if strings.HasPrefix(strings.ToUpper(item.Type), "CVSS") {
			score := item.Score
			if idx := strings.LastIndex(score, "/"); idx >= 0 {
				score = score[idx+1:]
			}
			parsed, err := strconv.ParseFloat(score, 64)
			if err == nil && parsed > max {
				max = parsed
			}
		}
	}
	return max
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
