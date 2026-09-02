package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
)

var ErrUpstreamQueueTimeout = errors.New("upstream request queue timed out")

type routeLimiters struct {
	mu      sync.Mutex
	byRoute map[string]chan struct{}
}

func (l *routeLimiters) limiter(route string, capacity int) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.byRoute == nil {
		l.byRoute = make(map[string]chan struct{})
	}
	if limiter, ok := l.byRoute[route]; ok {
		return limiter
	}
	limiter := make(chan struct{}, capacity)
	l.byRoute[route] = limiter
	return limiter
}

type routeCooldowns struct {
	mu      sync.Mutex
	byRoute map[string]time.Time
}

func (c *routeCooldowns) get(route string) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byRoute[route]
}

func (c *routeCooldowns) set(route string, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byRoute == nil {
		c.byRoute = make(map[string]time.Time)
	}
	if until.After(c.byRoute[route]) {
		c.byRoute[route] = until
	}
}

func (p *Proxy) do(request *http.Request, route config.RouteConfig) (*http.Response, error) {
	ctx := request.Context()
	cancel := func() {}
	if p.client.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, p.client.Timeout)
	}
	request = request.Clone(ctx)
	registry := upstreamRegistryKey(request)
	for attempt := 0; ; attempt++ {
		if response, err := p.waitForCooldown(ctx, request, registry, route.Name); response != nil || err != nil {
			if response != nil {
				response.Body = releaseOnClose(response.Body, cancel)
			} else {
				cancel()
			}
			return response, err
		}
		release, err := p.acquireUpstream(ctx, registry)
		if err != nil {
			if errors.Is(err, ErrUpstreamQueueTimeout) {
				p.recordUpstreamThrottled(route.Name, "queue_timeout")
			}
			cancel()
			return nil, err
		}
		p.recordUpstreamInFlight(route.Name, 1)
		response, err := p.doOnce(request.Clone(ctx), route)
		if err != nil {
			release()
			p.recordUpstreamInFlight(route.Name, -1)
			p.recordUpstreamRequest(route.Name, "error")
			cancel()
			return nil, err
		}
		response.Body = releaseOnClose(response.Body, func() {
			release()
			p.recordUpstreamInFlight(route.Name, -1)
		})
		p.recordUpstreamRequest(route.Name, strconv.Itoa(response.StatusCode))
		if response.StatusCode != http.StatusTooManyRequests {
			response.Body = releaseOnClose(response.Body, cancel)
			return response, nil
		}

		retryAfter := response.Header.Get("Retry-After")
		delay, valid := retryAfterDelay(retryAfter, p.now())
		if !valid {
			delay = p.rateLimitBackoff(attempt)
			response.Header.Set("Retry-After", retryAfterSeconds(delay))
		} else if delay > 0 {
			baseDelay := delay
			delay += p.jitter(min(delay/10, 250*time.Millisecond))
			if baseDelay <= p.upstream.MaxRetryAfter && delay > p.upstream.MaxRetryAfter {
				delay = p.upstream.MaxRetryAfter
			}
		}
		p.setCooldown(ctx, registry, route.Name, p.now().Add(delay))
		if !retryableRequest(request) || attempt >= p.upstream.RateLimitRetries || delay > p.upstream.MaxRetryAfter {
			response.Body = releaseOnClose(response.Body, cancel)
			return response, nil
		}
		drainAndClose(response.Body)
		p.recordUpstreamRetry(route.Name, "rate_limited")
		if err := p.wait(ctx, delay); err != nil {
			cancel()
			return nil, err
		}
	}
}

func (p *Proxy) acquireUpstream(ctx context.Context, registry string) (func(), error) {
	limiter := p.limiters.limiter(registry, p.upstream.MaxConcurrentPerRegistry)
	timer := time.NewTimer(p.upstream.QueueTimeout)
	defer timer.Stop()
	select {
	case limiter <- struct{}{}:
		return sync.OnceFunc(func() { <-limiter }), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, ErrUpstreamQueueTimeout
	}
}

func (p *Proxy) waitForCooldown(ctx context.Context, request *http.Request, registry, metricRoute string) (*http.Response, error) {
	until := p.cooldowns.get(registry)
	if p.coordination.Coordinator != nil {
		remote, err := p.coordination.Coordinator.Cooldown(ctx, "upstream:"+registry)
		if err != nil {
			p.logger.Warn("upstream_cooldown_read_failed", "route", metricRoute, "error", err)
		} else if remote.After(until) {
			until = remote
			p.cooldowns.set(registry, remote)
		}
	}
	remaining := until.Sub(p.now())
	if remaining <= 0 {
		return nil, nil
	}
	if remaining > p.upstream.MaxRetryAfter {
		p.recordUpstreamThrottled(metricRoute, "cooldown")
		return cooldownResponse(request, remaining), nil
	}
	p.recordUpstreamThrottled(metricRoute, "cooldown_wait")
	if err := p.wait(ctx, remaining); err != nil {
		return nil, err
	}
	return nil, nil
}

func (p *Proxy) setCooldown(ctx context.Context, registry, metricRoute string, until time.Time) {
	p.cooldowns.set(registry, until)
	if p.coordination.Coordinator == nil {
		return
	}
	if err := p.coordination.Coordinator.SetCooldown(ctx, "upstream:"+registry, until); err != nil {
		p.logger.Warn("upstream_cooldown_store_failed", "route", metricRoute, "error", err)
	}
}

func upstreamRegistryKey(request *http.Request) string {
	origin := request.URL.Scheme + "://" + request.URL.Host
	if normalized, err := config.NormalizeHTTPOrigin(origin); err == nil {
		return normalized
	}
	return strings.ToLower(origin)
}

func (p *Proxy) rateLimitBackoff(attempt int) time.Duration {
	maximum := time.Second << min(attempt, 5)
	if maximum > p.upstream.MaxRetryAfter {
		maximum = p.upstream.MaxRetryAfter
	}
	delay := p.jitter(maximum)
	minimum := min(100*time.Millisecond, maximum)
	if delay < minimum {
		return minimum
	}
	return delay
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

func retryAfterSeconds(delay time.Duration) string {
	seconds := (delay + time.Second - 1) / time.Second
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(int64(seconds), 10)
}

func retryableRequest(request *http.Request) bool {
	return (request.Method == http.MethodGet || request.Method == http.MethodHead) &&
		(request.Body == nil || request.Body == http.NoBody)
}

func cooldownResponse(request *http.Request, remaining time.Duration) *http.Response {
	body := "upstream registry is rate limited\n"
	return &http.Response{
		StatusCode:    http.StatusTooManyRequests,
		Status:        fmt.Sprintf("%d %s", http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests)),
		Header:        http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}, "Retry-After": []string{retryAfterSeconds(remaining)}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 32<<10))
	_ = body.Close()
}

type releasingBody struct {
	io.ReadCloser
	release func()
}

func releaseOnClose(body io.ReadCloser, release func()) io.ReadCloser {
	return &releasingBody{ReadCloser: body, release: sync.OnceFunc(release)}
}

func (b *releasingBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func randomJitter(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	return time.Duration(rand.Uint64N(uint64(maximum)))
}

type upstreamMetrics interface {
	UpstreamRequest(string, string)
	UpstreamInFlight(string, int)
	UpstreamRetry(string, string)
	UpstreamThrottled(string, string)
}

func (p *Proxy) recordUpstreamRequest(route, status string) {
	if metrics, ok := p.cache.Metrics.(upstreamMetrics); ok {
		metrics.UpstreamRequest(route, status)
	}
}

func (p *Proxy) recordUpstreamInFlight(route string, delta int) {
	if metrics, ok := p.cache.Metrics.(upstreamMetrics); ok {
		metrics.UpstreamInFlight(route, delta)
	}
}

func (p *Proxy) recordUpstreamRetry(route, reason string) {
	if metrics, ok := p.cache.Metrics.(upstreamMetrics); ok {
		metrics.UpstreamRetry(route, reason)
	}
}

func (p *Proxy) recordUpstreamThrottled(route, reason string) {
	if metrics, ok := p.cache.Metrics.(upstreamMetrics); ok {
		metrics.UpstreamThrottled(route, reason)
	}
}
