package prewarm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const cacheStatusHeader = "X-Package-Firewall-Cache"

type RunConfig struct {
	BaseURL           string
	RoutePrefix       string
	PluginRoutePrefix string
	Concurrency       int
	HTTPClient        *http.Client
	BearerToken       string
	BasicUsername     string
	BasicPassword     string
}

type PassStats struct {
	Artifacts int64
	Hits      int64
	Misses    int64
}

func Run(ctx context.Context, cfg RunConfig, artifacts []Artifact, output io.Writer) error {
	normalized, err := normalizeRunConfig(cfg)
	if err != nil {
		return err
	}
	if len(artifacts) == 0 {
		return errors.New("prewarm manifest contains no artifacts")
	}
	for _, artifact := range artifacts {
		if artifact.pluginMarker && normalized.PluginRoutePrefix == "" {
			return errors.New("prewarm plugin route prefix is required for active plugin markers")
		}
	}
	firstStats, selectedRoutes, err := runPass(ctx, normalized, artifacts, nil, false)
	if err != nil {
		return fmt.Errorf("prewarm pass 1: %w", err)
	}
	if err := writePassSummary(output, 1, firstStats); err != nil {
		return err
	}
	secondStats, _, err := runPass(ctx, normalized, artifacts, selectedRoutes, true)
	if err != nil {
		return fmt.Errorf("prewarm pass 2: %w", err)
	}
	if err := writePassSummary(output, 2, secondStats); err != nil {
		return err
	}
	return nil
}

func writePassSummary(output io.Writer, pass int, stats PassStats) error {
	if output == nil {
		return nil
	}
	if _, err := fmt.Fprintf(output, "pass=%d artifacts=%d cache_hits=%d cache_misses=%d\n", pass, stats.Artifacts, stats.Hits, stats.Misses); err != nil {
		return fmt.Errorf("write prewarm pass %d summary: %w", pass, err)
	}
	return nil
}

func normalizeRunConfig(cfg RunConfig) (RunConfig, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(cfg.BaseURL))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return RunConfig{}, errors.New("prewarm base URL must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return RunConfig{}, errors.New("prewarm base URL must not include credentials, a query, or a fragment")
	}
	if cfg.Concurrency == 0 {
		cfg.Concurrency = 2
	}
	if cfg.Concurrency < 1 || cfg.Concurrency > 16 {
		return RunConfig{}, errors.New("prewarm concurrency must be between 1 and 16")
	}
	if (cfg.BasicUsername == "") != (cfg.BasicPassword == "") {
		return RunConfig{}, errors.New("prewarm basic username and password must be set together")
	}
	if cfg.BearerToken != "" && cfg.BasicUsername != "" {
		return RunConfig{}, errors.New("prewarm bearer and basic authentication cannot both be set")
	}
	if cfg.RoutePrefix == "" {
		cfg.RoutePrefix = "/maven/"
	}
	routePrefix, err := normalizeRoutePrefix(cfg.RoutePrefix)
	if err != nil {
		return RunConfig{}, fmt.Errorf("prewarm route prefix: %w", err)
	}
	cfg.RoutePrefix = routePrefix
	if cfg.PluginRoutePrefix != "" {
		pluginRoutePrefix, err := normalizeRoutePrefix(cfg.PluginRoutePrefix)
		if err != nil {
			return RunConfig{}, fmt.Errorf("prewarm plugin route prefix: %w", err)
		}
		if pluginRoutePrefix == cfg.RoutePrefix {
			return RunConfig{}, errors.New("prewarm Maven and plugin route prefixes must differ")
		}
		cfg.PluginRoutePrefix = pluginRoutePrefix
	}
	cfg.BaseURL = strings.TrimRight(parsed.String(), "/")
	client := &http.Client{Timeout: 10 * time.Minute}
	if cfg.HTTPClient != nil {
		copy := *cfg.HTTPClient
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = 10 * time.Minute
		}
	}
	origin := strings.ToLower(parsed.Scheme + "://" + parsed.Host)
	configuredRedirect := client.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if strings.ToLower(request.URL.Scheme+"://"+request.URL.Host) != origin {
			return errors.New("prewarm redirect changed origin")
		}
		if configuredRedirect != nil {
			return configuredRedirect(request, via)
		}
		if len(via) >= 10 {
			return errors.New("prewarm redirect limit exceeded")
		}
		return nil
	}
	cfg.HTTPClient = client
	return cfg, nil
}

func normalizeRoutePrefix(value string) (string, error) {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#") {
		return "", errors.New("must be an absolute URL path")
	}
	return "/" + strings.Trim(value, "/") + "/", nil
}

type artifactJob struct {
	index    int
	artifact Artifact
}

func runPass(parent context.Context, cfg RunConfig, artifacts []Artifact, selectedRoutes []string, requireHit bool) (PassStats, []string, error) {
	if selectedRoutes != nil && len(selectedRoutes) != len(artifacts) {
		return PassStats{}, nil, errors.New("selected prewarm routes do not match artifact manifest")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	jobs := make(chan artifactJob)
	var stats PassStats
	discoveredRoutes := make([]string, len(artifacts))
	var firstErr error
	var errOnce sync.Once
	var unavailable []Artifact
	var unavailableMu sync.Mutex
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}
	var workers sync.WaitGroup
	for range cfg.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				routes := routeCandidates(cfg, job.artifact)
				if selectedRoutes != nil {
					routes = []string{selectedRoutes[job.index]}
				}
				status, route, found, err := fetchArtifact(ctx, cfg, job.artifact, routes)
				if err != nil {
					fail(fmt.Errorf("%s: %w", job.artifact.Path, err))
					return
				}
				if !found {
					unavailableMu.Lock()
					unavailable = append(unavailable, job.artifact)
					unavailableMu.Unlock()
					continue
				}
				discoveredRoutes[job.index] = route
				if requireHit && status != "HIT" {
					fail(fmt.Errorf("%s: second pass returned cache status %q, expected HIT", job.artifact.Path, status))
					return
				}
				atomic.AddInt64(&stats.Artifacts, 1)
				switch status {
				case "HIT":
					atomic.AddInt64(&stats.Hits, 1)
				case "MISS":
					atomic.AddInt64(&stats.Misses, 1)
				default:
					fail(fmt.Errorf("%s: unexpected cache status %q", job.artifact.Path, status))
					return
				}
			}
		}()
	}
send:
	for index, artifact := range artifacts {
		select {
		case jobs <- artifactJob{index: index, artifact: artifact}:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	if firstErr != nil {
		return PassStats{}, nil, firstErr
	}
	if err := parent.Err(); err != nil {
		return PassStats{}, nil, err
	}
	if len(unavailable) > 0 {
		return PassStats{}, nil, unavailableArtifactsError(unavailable)
	}
	return stats, discoveredRoutes, nil
}

func routeCandidates(cfg RunConfig, artifact Artifact) []string {
	if artifact.pluginMarker && cfg.PluginRoutePrefix != "" {
		return []string{cfg.PluginRoutePrefix}
	}
	return []string{cfg.RoutePrefix}
}

func fetchArtifact(ctx context.Context, cfg RunConfig, artifact Artifact, routes []string) (string, string, bool, error) {
	for _, route := range routes {
		status, found, err := fetchArtifactFromRoute(ctx, cfg, artifact, route)
		if err != nil {
			return "", "", false, err
		}
		if found {
			return status, route, true, nil
		}
	}
	return "", "", false, nil
}

func fetchArtifactFromRoute(ctx context.Context, cfg RunConfig, artifact Artifact, route string) (string, bool, error) {
	target, err := url.JoinPath(cfg.BaseURL, route, artifact.Path)
	if err != nil {
		return "", false, fmt.Errorf("build request URL: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", false, fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept-Encoding", "identity")
	if cfg.BearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	} else if cfg.BasicUsername != "" {
		request.SetBasicAuth(cfg.BasicUsername, cfg.BasicPassword)
	}
	response, err := cfg.HTTPClient.Do(request)
	if err != nil {
		return "", false, fmt.Errorf("request package firewall: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		_, _ = io.Copy(io.Discard, response.Body)
		return "", false, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode == http.StatusTooManyRequests {
			return "", false, fmt.Errorf("package firewall returned 429 with Retry-After %q", response.Header.Get("Retry-After"))
		}
		return "", false, fmt.Errorf("package firewall returned HTTP %d", response.StatusCode)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, response.Body); err != nil {
		return "", false, fmt.Errorf("read response: %w", err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !containsChecksum(artifact.SHA256, actual) {
		return "", false, fmt.Errorf("SHA-256 mismatch: got %s", actual)
	}
	return strings.ToUpper(strings.TrimSpace(response.Header.Get(cacheStatusHeader))), true, nil
}

func unavailableArtifactsError(artifacts []Artifact) error {
	coordinates := make(map[string]struct{})
	for _, artifact := range artifacts {
		coordinate := artifact.Coordinate
		if coordinate == "" {
			coordinate = artifact.Path
		}
		coordinates[coordinate] = struct{}{}
	}
	values := make([]string, 0, len(coordinates))
	for coordinate := range coordinates {
		values = append(values, coordinate)
	}
	sort.Strings(values)
	return fmt.Errorf("%d artifacts across %d coordinates are unavailable from configured Package Firewall routes: %s", len(artifacts), len(values), strings.Join(values, ", "))
}

func containsChecksum(checksums []string, actual string) bool {
	for _, checksum := range checksums {
		if strings.EqualFold(checksum, actual) {
			return true
		}
	}
	return false
}
