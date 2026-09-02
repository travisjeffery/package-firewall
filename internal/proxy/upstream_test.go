package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
)

func TestProxyLimitsConcurrencyPerUpstreamRegistry(t *testing.T) {
	const requestCount = 12
	var inFlight atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, requestCount)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxy := newTestUpstreamProxy(UpstreamProtectionConfig{
		MaxConcurrentPerRegistry: 2,
		QueueTimeout:             time.Second,
		RateLimitRetries:         0,
		MaxRetryAfter:            30 * time.Second,
	})
	results := make(chan error, requestCount)
	for index := range requestCount {
		go func() {
			request, err := http.NewRequest(http.MethodGet, upstream.URL+"/artifact", nil)
			if err != nil {
				results <- err
				return
			}
			route := config.RouteConfig{Name: "maven-a", UpstreamURL: upstream.URL + "/"}
			if index%2 == 1 {
				route.Name = "maven-b"
			}
			response, err := proxy.do(request, route)
			if err == nil {
				_, readErr := io.Copy(io.Discard, response.Body)
				err = errors.Join(readErr, response.Body.Close())
			}
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("two upstream requests did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("more than two requests reached the shared upstream registry")
	case <-time.After(50 * time.Millisecond):
	}
	releaseAll()
	for range requestCount {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if got := maximum.Load(); got != 2 {
		t.Fatalf("maximum upstream concurrency = %d want 2", got)
	}
}

func TestProxyBoundsUpstreamQueueWait(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	proxy := newTestUpstreamProxy(UpstreamProtectionConfig{
		MaxConcurrentPerRegistry: 1,
		QueueTimeout:             20 * time.Millisecond,
		RateLimitRetries:         0,
		MaxRetryAfter:            30 * time.Second,
	})
	route := config.RouteConfig{Name: "maven", UpstreamURL: upstream.URL + "/"}
	first := make(chan error, 1)
	go func() {
		request, err := http.NewRequest(http.MethodGet, upstream.URL+"/first", nil)
		if err == nil {
			var response *http.Response
			response, err = proxy.do(request, route)
			if err == nil {
				_, readErr := io.Copy(io.Discard, response.Body)
				err = errors.Join(readErr, response.Body.Close())
			}
		}
		first <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first upstream request did not start")
	}
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/second", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.do(request, route); !errors.Is(err, ErrUpstreamQueueTimeout) {
		t.Fatalf("queue error = %v want %v", err, ErrUpstreamQueueTimeout)
	}
	releaseAll()
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

func TestProxyRetriesRateLimitAfterServerDelay(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "slow down")
			return
		}
		_, _ = io.WriteString(w, "artifact")
	}))
	defer upstream.Close()

	proxy := newTestUpstreamProxy(UpstreamProtectionConfig{
		MaxConcurrentPerRegistry: 1,
		QueueTimeout:             time.Second,
		RateLimitRetries:         1,
		MaxRetryAfter:            30 * time.Second,
	})
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	proxy.now = func() time.Time { return now }
	var waits []time.Duration
	proxy.wait = func(ctx context.Context, delay time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		waits = append(waits, delay)
		now = now.Add(delay)
		return nil
	}
	proxy.jitter = func(time.Duration) time.Duration { return 0 }
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := proxy.do(request, config.RouteConfig{Name: "maven", UpstreamURL: upstream.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "artifact" {
		t.Fatalf("status = %d body = %q", response.StatusCode, body)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d want 2", hits.Load())
	}
	if len(waits) != 1 || waits[0] != 2*time.Second {
		t.Fatalf("waits = %v want [2s]", waits)
	}
}

func TestProxySharesLongRateLimitCooldownAcrossReplicas(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, "rate limited")
	}))
	defer upstream.Close()

	coordinator := newMemoryCoordinator()
	newReplica := func() *Proxy {
		proxy := newTestUpstreamProxy(UpstreamProtectionConfig{
			MaxConcurrentPerRegistry: 2,
			QueueTimeout:             time.Second,
			RateLimitRetries:         1,
			MaxRetryAfter:            30 * time.Second,
		})
		proxy.coordination.Coordinator = coordinator
		proxy.now = func() time.Time { return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) }
		proxy.jitter = func(time.Duration) time.Duration { return 0 }
		return proxy
	}
	route := config.RouteConfig{Name: "maven", UpstreamURL: upstream.URL + "/"}
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := newReplica().do(request, route)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Body.Close()

	request, err = http.NewRequest(http.MethodGet, upstream.URL+"/artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newReplica().do(request, route)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(second.Body)
	if err := errors.Join(readErr, second.Body.Close()); err != nil {
		t.Fatal(err)
	}
	if second.StatusCode != http.StatusTooManyRequests || second.Header.Get("Retry-After") != "120" {
		t.Fatalf("status = %d Retry-After = %q", second.StatusCode, second.Header.Get("Retry-After"))
	}
	if string(body) != "upstream registry is rate limited\n" {
		t.Fatalf("body = %q", body)
	}
	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d want 1", hits.Load())
	}
}

func TestUpstreamRequestContextLivesUntilResponseBodyClose(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(w, "complete-body")
	}))
	defer upstream.Close()
	proxy := newTestUpstreamProxy(UpstreamProtectionConfig{
		MaxConcurrentPerRegistry: 1,
		QueueTimeout:             time.Second,
		RateLimitRetries:         0,
		MaxRetryAfter:            time.Second,
	})
	request, err := http.NewRequest(http.MethodGet, upstream.URL+"/artifact", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := proxy.do(request, config.RouteConfig{Name: "maven", UpstreamURL: upstream.URL + "/"})
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	if err := errors.Join(readErr, response.Body.Close()); err != nil {
		t.Fatal(err)
	}
	if string(body) != "complete-body" {
		t.Fatalf("body = %q", body)
	}
}

func TestRetryAfterDelay(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		value string
		want  time.Duration
		valid bool
	}{
		{value: "15", want: 15 * time.Second, valid: true},
		{value: "0", valid: true},
		{value: now.Add(45 * time.Second).Format(http.TimeFormat), want: 45 * time.Second, valid: true},
		{value: now.Add(-time.Second).Format(http.TimeFormat), valid: true},
		{value: "invalid"},
		{value: "-1"},
	}
	for _, test := range tests {
		got, valid := retryAfterDelay(test.value, now)
		if got != test.want || valid != test.valid {
			t.Fatalf("retryAfterDelay(%q) = (%s, %v) want (%s, %v)", test.value, got, valid, test.want, test.valid)
		}
	}
}

func newTestUpstreamProxy(protection UpstreamProtectionConfig) *Proxy {
	return New(
		"http://firewall.test",
		WithHTTPClient(&http.Client{Timeout: 2 * time.Second}),
		WithUpstreamProtection(protection),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
}

func TestReleaseOnCloseIsIdempotent(t *testing.T) {
	var releases atomic.Int32
	body := releaseOnClose(io.NopCloser(&lockedReader{body: "ok"}), func() { releases.Add(1) })
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	if releases.Load() != 1 {
		t.Fatalf("releases = %d want 1", releases.Load())
	}
}

type lockedReader struct {
	mu   sync.Mutex
	body string
}

func (r *lockedReader) Read(destination []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.body == "" {
		return 0, io.EOF
	}
	written := copy(destination, r.body)
	r.body = r.body[written:]
	return written, nil
}
