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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const cacheStatusHeader = "X-Package-Firewall-Cache"

type RunConfig struct {
	BaseURL            string
	RoutePrefix        string
	PluginRoutePrefix  string
	Concurrency        int
	MinRequestInterval time.Duration
	RateLimitRetries   int
	StateFile          string
	HTTPClient         *http.Client
	BearerToken        string
	BasicUsername      string
	BasicPassword      string
	Progress           io.Writer
	progress           *progressLogger
	pass               int
	total              int
	attempt            int
}

type PassStats struct {
	Artifacts int64
	Hits      int64
	Misses    int64
}

func Run(ctx context.Context, cfg RunConfig, artifacts []Artifact, output io.Writer) (runErr error) {
	normalized, err := normalizeRunConfig(cfg)
	if err != nil {
		return err
	}
	normalized.progress = newProgressLogger(cfg.Progress)
	defer func() {
		if normalized.progress != nil && normalized.progress.err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write prewarm progress: %w", normalized.progress.err))
		}
	}()
	if len(artifacts) == 0 {
		return errors.New("prewarm manifest contains no artifacts")
	}
	for _, artifact := range artifacts {
		if artifact.pluginMarker && normalized.PluginRoutePrefix == "" {
			return errors.New("prewarm plugin route prefix is required for active plugin markers")
		}
	}
	checkpoint, err := loadCheckpoint(normalized.StateFile, normalized, artifacts)
	if err != nil {
		return err
	}
	firstStats, selectedRoutes, err := runPass(ctx, normalized, artifacts, nil, false, checkpoint)
	if err != nil {
		return fmt.Errorf("prewarm pass 1: %w", err)
	}
	if err := writePassSummary(output, 1, firstStats); err != nil {
		return err
	}
	secondStats, _, err := runPass(ctx, normalized, artifacts, selectedRoutes, true, nil)
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
	if cfg.MinRequestInterval < 0 {
		return RunConfig{}, errors.New("prewarm minimum request interval must not be negative")
	}
	if cfg.RateLimitRetries == 0 {
		cfg.RateLimitRetries = 1
	}
	if cfg.RateLimitRetries < 1 || cfg.RateLimitRetries > 16 {
		return RunConfig{}, errors.New("prewarm rate-limit retries must be between 1 and 16")
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

type requestPacer struct {
	minInterval time.Duration
	mu          sync.Mutex
	next        time.Time
}

func newRequestPacer(minInterval time.Duration) *requestPacer {
	if minInterval == 0 {
		return nil
	}
	return &requestPacer{minInterval: minInterval}
}

func (p *requestPacer) do(ctx context.Context, client *http.Client, request *http.Request, onStart func()) (*http.Response, error) {
	if p == nil {
		onStart()
		return client.Do(request)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if delay := time.Until(p.next); delay > 0 {
		if err := waitContext(ctx, delay); err != nil {
			return nil, err
		}
	}
	p.next = time.Now().Add(p.minInterval)
	onStart()
	return client.Do(request)
}

func runPass(parent context.Context, cfg RunConfig, artifacts []Artifact, selectedRoutes []string, requireHit bool, checkpoint *checkpoint) (PassStats, []string, error) {
	cfg.pass, cfg.total = 1, len(artifacts)
	if requireHit {
		cfg.pass = 2
	}
	if selectedRoutes != nil && len(selectedRoutes) != len(artifacts) {
		return PassStats{}, nil, errors.New("selected prewarm routes do not match artifact manifest")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	jobs := make(chan artifactJob)
	var stats PassStats
	passStarted := time.Now()
	cfg.emit(progressEvent{Event: "pass_start"})
	defer func() {
		cfg.emit(progressEvent{Event: "pass_end", Completed: atomic.LoadInt64(&stats.Artifacts), ElapsedMS: time.Since(passStarted).Milliseconds()})
	}()
	discoveredRoutes := make([]string, len(artifacts))
	var firstErr error
	var errOnce sync.Once
	var unavailable []Artifact
	var unavailableMu sync.Mutex
	pacer := newRequestPacer(0)
	if !requireHit {
		pacer = newRequestPacer(cfg.MinRequestInterval)
	}
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
				started := time.Now()
				jobCfg := cfg
				jobCfg.emit(progressEvent{Event: "artifact_start", Artifact: job.artifact.Path})
				if checkpoint != nil {
					if entry, ok := checkpoint.completed(job.artifact); ok {
						discoveredRoutes[job.index] = entry.Route
						atomic.AddInt64(&stats.Artifacts, 1)
						switch entry.Status {
						case "HIT":
							atomic.AddInt64(&stats.Hits, 1)
						case "MISS":
							atomic.AddInt64(&stats.Misses, 1)
						default:
							fail(fmt.Errorf("%s: checkpoint has unexpected cache status %q", job.artifact.Path, entry.Status))
							return
						}
						jobCfg.emit(progressEvent{Event: "artifact_complete", Artifact: job.artifact.Path, Route: entry.Route, CacheStatus: entry.Status, Outcome: "checkpoint", Completed: atomic.LoadInt64(&stats.Artifacts), ElapsedMS: time.Since(started).Milliseconds()})
						continue
					}
				}
				rateLimitAttempts := 0
				var status, route string
				var found bool
				var err error
				for {
					routes := routeCandidates(cfg, job.artifact)
					if selectedRoutes != nil {
						routes = []string{selectedRoutes[job.index]}
					}
					jobCfg.attempt = rateLimitAttempts + 1
					status, route, found, err = fetchArtifact(ctx, jobCfg, pacer, job.artifact, routes)
					if err == nil {
						break
					}
					var rateErr *rateLimitError
					if !errors.As(err, &rateErr) {
						break
					}
					if rateLimitAttempts >= cfg.RateLimitRetries {
						err = fmt.Errorf("%w after %d retries", err, rateLimitAttempts)
						break
					}
					rateLimitAttempts++
					delay := rateErr.Delay
					if !rateErr.Valid {
						delay = rateLimitBackoff(rateLimitAttempts - 1)
					}
					jobCfg.emit(progressEvent{Event: "retry_wait", Artifact: job.artifact.Path, RetryDelayMS: delay.Milliseconds(), RetryAfter: rateErr.Valid, ElapsedMS: time.Since(started).Milliseconds()})
					if err := waitContext(ctx, delay); err != nil {
						return
					}
				}
				if err != nil {
					jobCfg.emit(progressEvent{Event: "artifact_failed", Artifact: job.artifact.Path, ElapsedMS: time.Since(started).Milliseconds()})
					fail(fmt.Errorf("%s: %w", job.artifact.Path, err))
					return
				}
				if !found {
					jobCfg.emit(progressEvent{Event: "artifact_failed", Artifact: job.artifact.Path, Outcome: "not_found", ElapsedMS: time.Since(started).Milliseconds()})
					unavailableMu.Lock()
					unavailable = append(unavailable, job.artifact)
					unavailableMu.Unlock()
					continue
				}
				discoveredRoutes[job.index] = route
				if requireHit && status != "HIT" {
					jobCfg.emit(progressEvent{Event: "artifact_failed", Artifact: job.artifact.Path, Outcome: "expected_hit", ElapsedMS: time.Since(started).Milliseconds()})
					fail(fmt.Errorf("%s: second pass returned cache status %q, expected HIT", job.artifact.Path, status))
					return
				}
				if checkpoint != nil {
					if err := checkpoint.record(job.artifact, route, status); err != nil {
						fail(fmt.Errorf("%s: save checkpoint: %w", job.artifact.Path, err))
						return
					}
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
				jobCfg.emit(progressEvent{Event: "artifact_complete", Artifact: job.artifact.Path, Route: route, CacheStatus: status, Outcome: "verified", Completed: atomic.LoadInt64(&stats.Artifacts), ElapsedMS: time.Since(started).Milliseconds()})
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

func fetchArtifact(ctx context.Context, cfg RunConfig, pacer *requestPacer, artifact Artifact, routes []string) (string, string, bool, error) {
	for _, route := range routes {
		status, found, err := fetchArtifactFromRoute(ctx, cfg, pacer, artifact, route)
		if err != nil {
			return "", "", false, err
		}
		if found {
			return status, route, true, nil
		}
	}
	return "", "", false, nil
}

type rateLimitError struct {
	Delay  time.Duration
	Valid  bool
	Header string
}

func (e *rateLimitError) Error() string {
	return fmt.Sprintf("package firewall returned 429 with Retry-After %q", e.Header)
}

func rateLimitBackoff(attempt int) time.Duration {
	return time.Second << min(attempt, 5)
}

func waitContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func fetchArtifactFromRoute(ctx context.Context, cfg RunConfig, pacer *requestPacer, artifact Artifact, route string) (string, bool, error) {
	started := time.Now()
	var sent, headers time.Time
	event := progressEvent{Event: "request_start", Artifact: artifact.Path, Route: route}
	cfg.emit(event)
	defer func() {
		event.Event = "request_end"
		event.ElapsedMS = time.Since(started).Milliseconds()
		if !headers.IsZero() {
			event.BodyMS = time.Since(headers).Milliseconds()
		}
		cfg.emit(event)
	}()
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
	response, err := pacer.do(ctx, cfg.HTTPClient, request, func() {
		sent = time.Now()
		event.PacingMS = sent.Sub(started).Milliseconds()
		cfg.emit(progressEvent{Event: "request_sent", Artifact: artifact.Path, Route: route, PacingMS: event.PacingMS})
	})
	if !sent.IsZero() {
		event.HeadersMS = time.Since(sent).Milliseconds()
	}
	if err != nil {
		event.Outcome = "transport_error"
		return "", false, fmt.Errorf("request package firewall: %w", err)
	}
	defer response.Body.Close()
	headers = time.Now()
	event.HTTPStatus = response.StatusCode
	event.CacheStatus = strings.ToUpper(strings.TrimSpace(response.Header.Get(cacheStatusHeader)))
	event.RequestID = response.Header.Get("X-Request-ID")
	event.Event = "request_headers"
	cfg.emit(event)
	if response.StatusCode == http.StatusNotFound {
		event.Outcome = "not_found"
		event.Bytes, _ = io.Copy(io.Discard, response.Body)
		return "", false, nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		event.Outcome = "http_error"
		if response.StatusCode == http.StatusTooManyRequests {
			event.Outcome = "rate_limited"
			header := strings.TrimSpace(response.Header.Get("Retry-After"))
			delay, valid := retryAfterDelay(header, time.Now())
			return "", false, &rateLimitError{Delay: delay, Valid: valid, Header: header}
		}
		return "", false, fmt.Errorf("package firewall returned HTTP %d", response.StatusCode)
	}
	hasher := sha256.New()
	event.Outcome = "body_error"
	event.Bytes, err = io.Copy(hasher, response.Body)
	if err != nil {
		return "", false, fmt.Errorf("read response: %w", err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if !containsChecksum(artifact.SHA256, actual) {
		event.Outcome = "checksum_mismatch"
		return "", false, fmt.Errorf("SHA-256 mismatch: got %s", actual)
	}
	event.Outcome = "verified"
	return strings.ToUpper(strings.TrimSpace(response.Header.Get(cacheStatusHeader))), true, nil
}

func retryAfterDelay(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 32); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return max(when.Sub(now), 0), true
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
