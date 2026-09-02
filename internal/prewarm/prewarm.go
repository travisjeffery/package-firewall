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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const cacheStatusHeader = "X-Package-Firewall-Cache"

type RunConfig struct {
	BaseURL       string
	RoutePrefix   string
	Concurrency   int
	HTTPClient    *http.Client
	BearerToken   string
	BasicUsername string
	BasicPassword string
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
	for pass := 1; pass <= 2; pass++ {
		stats, err := runPass(ctx, normalized, artifacts, pass == 2)
		if err != nil {
			return fmt.Errorf("prewarm pass %d: %w", pass, err)
		}
		if output != nil {
			if _, err := fmt.Fprintf(output, "pass=%d artifacts=%d cache_hits=%d cache_misses=%d\n", pass, stats.Artifacts, stats.Hits, stats.Misses); err != nil {
				return fmt.Errorf("write prewarm pass %d summary: %w", pass, err)
			}
		}
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
	if !strings.HasPrefix(cfg.RoutePrefix, "/") || strings.ContainsAny(cfg.RoutePrefix, "?#") {
		return RunConfig{}, errors.New("prewarm route prefix must be an absolute URL path")
	}
	cfg.RoutePrefix = "/" + strings.Trim(cfg.RoutePrefix, "/") + "/"
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

func runPass(parent context.Context, cfg RunConfig, artifacts []Artifact, requireHit bool) (PassStats, error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	jobs := make(chan Artifact)
	var stats PassStats
	var firstErr error
	var errOnce sync.Once
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
			for artifact := range jobs {
				status, err := fetchArtifact(ctx, cfg, artifact)
				if err != nil {
					fail(fmt.Errorf("%s: %w", artifact.Path, err))
					return
				}
				if requireHit && status != "HIT" {
					fail(fmt.Errorf("%s: second pass returned cache status %q, expected HIT", artifact.Path, status))
					return
				}
				atomic.AddInt64(&stats.Artifacts, 1)
				switch status {
				case "HIT":
					atomic.AddInt64(&stats.Hits, 1)
				case "MISS":
					atomic.AddInt64(&stats.Misses, 1)
				default:
					fail(fmt.Errorf("%s: unexpected cache status %q", artifact.Path, status))
					return
				}
			}
		}()
	}
send:
	for _, artifact := range artifacts {
		select {
		case jobs <- artifact:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	if firstErr != nil {
		return PassStats{}, firstErr
	}
	if err := parent.Err(); err != nil {
		return PassStats{}, err
	}
	return stats, nil
}

func fetchArtifact(ctx context.Context, cfg RunConfig, artifact Artifact) (string, error) {
	target, err := url.JoinPath(cfg.BaseURL, cfg.RoutePrefix, artifact.Path)
	if err != nil {
		return "", fmt.Errorf("build request URL: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Accept-Encoding", "identity")
	if cfg.BearerToken != "" {
		request.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	} else if cfg.BasicUsername != "" {
		request.SetBasicAuth(cfg.BasicUsername, cfg.BasicPassword)
	}
	response, err := cfg.HTTPClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("request package firewall: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode == http.StatusTooManyRequests {
			return "", fmt.Errorf("package firewall returned 429 with Retry-After %q", response.Header.Get("Retry-After"))
		}
		return "", fmt.Errorf("package firewall returned HTTP %d", response.StatusCode)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, response.Body); err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !containsChecksum(artifact.SHA256, actual) {
		return "", fmt.Errorf("SHA-256 mismatch: got %s", actual)
	}
	return strings.ToUpper(strings.TrimSpace(response.Header.Get(cacheStatusHeader))), nil
}

func containsChecksum(checksums []string, actual string) bool {
	for _, checksum := range checksums {
		if strings.EqualFold(checksum, actual) {
			return true
		}
	}
	return false
}
