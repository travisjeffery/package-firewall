package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/travisjeffery/tidewaiter/internal/artifactcache"
	"github.com/travisjeffery/tidewaiter/internal/config"
	"github.com/travisjeffery/tidewaiter/internal/coordination"
	"github.com/travisjeffery/tidewaiter/internal/registry"
)

const (
	cacheHeader                          = "X-Package-Firewall-Cache"
	defaultCacheReadTimeout              = 30 * time.Second
	defaultCacheStoreTimeout             = 10 * time.Minute
	defaultCoordinationLeaseDuration     = 30 * time.Second
	defaultCoordinationPollInterval      = time.Second
	defaultUpstreamMaxConcurrentRegistry = 4
	defaultUpstreamQueueTimeout          = 15 * time.Second
	defaultUpstreamRateLimitRetries      = 1
	defaultUpstreamMaxRetryAfter         = 30 * time.Second
	defaultUpstreamRequestTimeout        = 9 * time.Minute
	defaultUpstreamResponseHeaderTimeout = 30 * time.Second
	maxUpstreamRedirects                 = 10
)

var (
	errObjectTooLarge           = errors.New("artifact exceeds cache object limit")
	errUnsafeUpstreamRedirect   = errors.New("upstream redirect changes origin")
	errUpstreamRedirectLimit    = errors.New("upstream redirect limit exceeded")
	errUnreplayableBodyRedirect = errors.New("upstream redirect requires replaying a streaming request body")
	errEncodedRewriteBody       = errors.New("upstream sent an encoded body that must be rewritten")
)

type CacheMetrics interface {
	Hit(route string)
	Miss(route string)
	StoreError(route string)
	ReadError(route string)
	Bypass(route, reason string)
}

type CacheConfig struct {
	Store         artifactcache.Store
	ArtifactTTL   time.Duration
	MaxObjectSize int64
	TempDirectory string
	ReadTimeout   time.Duration
	StoreTimeout  time.Duration
	Metrics       CacheMetrics
}

type CoordinationConfig struct {
	Coordinator   coordination.Coordinator
	LeaseDuration time.Duration
	PollInterval  time.Duration
}

type UpstreamProtectionConfig struct {
	MaxConcurrentPerRegistry int
	QueueTimeout             time.Duration
	RateLimitRetries         int
	MaxRetryAfter            time.Duration
}

type Option func(*Proxy)

func WithCache(cfg CacheConfig) Option {
	return func(proxy *Proxy) {
		proxy.cache = cfg
		if proxy.cache.Metrics == nil {
			proxy.cache.Metrics = noopCacheMetrics{}
		}
		if proxy.cache.ReadTimeout <= 0 {
			proxy.cache.ReadTimeout = defaultCacheReadTimeout
		}
		if proxy.cache.StoreTimeout <= 0 {
			proxy.cache.StoreTimeout = defaultCacheStoreTimeout
		}
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(proxy *Proxy) {
		if client != nil {
			proxy.client = client
		}
	}
}

func WithCoordination(cfg CoordinationConfig) Option {
	return func(proxy *Proxy) {
		proxy.coordination = cfg
		if proxy.coordination.LeaseDuration <= 0 {
			proxy.coordination.LeaseDuration = defaultCoordinationLeaseDuration
		}
		if proxy.coordination.PollInterval <= 0 {
			proxy.coordination.PollInterval = defaultCoordinationPollInterval
		}
	}
}

func WithUpstreamProtection(cfg UpstreamProtectionConfig) Option {
	return func(proxy *Proxy) {
		proxy.upstream = cfg
		if proxy.upstream.MaxConcurrentPerRegistry <= 0 {
			proxy.upstream.MaxConcurrentPerRegistry = defaultUpstreamMaxConcurrentRegistry
		}
		if proxy.upstream.QueueTimeout <= 0 {
			proxy.upstream.QueueTimeout = defaultUpstreamQueueTimeout
		}
		if proxy.upstream.RateLimitRetries < 0 {
			proxy.upstream.RateLimitRetries = defaultUpstreamRateLimitRetries
		}
		if proxy.upstream.MaxRetryAfter <= 0 {
			proxy.upstream.MaxRetryAfter = defaultUpstreamMaxRetryAfter
		}
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(proxy *Proxy) {
		if logger != nil {
			proxy.logger = logger
		}
	}
}

type Proxy struct {
	client       *http.Client
	baseURL      string
	cache        CacheConfig
	coordination CoordinationConfig
	upstream     UpstreamProtectionConfig
	fills        fillGroup
	limiters     routeLimiters
	cooldowns    routeCooldowns
	logger       *slog.Logger
	createTemp   func(string, string) (*os.File, error)
	now          func() time.Time
	wait         func(context.Context, time.Duration) error
	jitter       func(time.Duration) time.Duration
	startStore   func(func())
}

func New(baseURL string, options ...Option) *Proxy {
	proxy := &Proxy{
		client:     NewHTTPClient(defaultUpstreamRequestTimeout, defaultUpstreamResponseHeaderTimeout),
		baseURL:    strings.TrimRight(baseURL, "/"),
		logger:     slog.Default(),
		createTemp: createCacheTemp,
		now:        time.Now,
		startStore: func(store func()) { go store() },
		cache: CacheConfig{
			Metrics: noopCacheMetrics{},
		},
		coordination: CoordinationConfig{
			LeaseDuration: defaultCoordinationLeaseDuration,
			PollInterval:  defaultCoordinationPollInterval,
		},
		upstream: UpstreamProtectionConfig{
			MaxConcurrentPerRegistry: defaultUpstreamMaxConcurrentRegistry,
			QueueTimeout:             defaultUpstreamQueueTimeout,
			RateLimitRetries:         defaultUpstreamRateLimitRetries,
			MaxRetryAfter:            defaultUpstreamMaxRetryAfter,
		},
		wait:   waitContext,
		jitter: randomJitter,
	}
	for _, option := range options {
		option(proxy)
	}
	return proxy
}

// NewHTTPClient returns a reusable upstream client with bounded header and
// complete-response lifetimes.
func NewHTTPClient(requestTimeout, responseHeaderTimeout time.Duration) *http.Client {
	if requestTimeout <= 0 {
		requestTimeout = defaultUpstreamRequestTimeout
	}
	if responseHeaderTimeout <= 0 {
		responseHeaderTimeout = defaultUpstreamResponseHeaderTimeout
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseHeaderTimeout
	return &http.Client{Transport: transport, Timeout: requestTimeout}
}

type Result struct {
	StatusCode int
}

func (p *Proxy) Serve(w http.ResponseWriter, r *http.Request, route config.RouteConfig, info registry.RequestInfo) (Result, error) {
	target, err := upstreamURL(route, info)
	if err != nil {
		return Result{}, err
	}
	target, err = withRequestQuery(target, r.URL)
	if err != nil {
		return Result{}, err
	}
	cacheKey, bypassReason := p.cacheKey(r, route, info, target)
	if bypassReason == "" {
		cached, cacheErr := p.loadCached(r, cacheKey)
		switch {
		case cacheErr == nil:
			defer cached.Close()
			p.cache.Metrics.Hit(route.Name)
			return serveCached(w, cached, p.now())
		case errors.Is(cacheErr, artifactcache.ErrNotFound):
			p.cache.Metrics.Miss(route.Name)
		default:
			p.cache.Metrics.ReadError(route.Name)
			p.cache.Metrics.Miss(route.Name)
			p.logger.Warn("artifact_cache_read_failed", "route", route.Name, "error", cacheErr)
		}
		w.Header().Set(cacheHeader, "MISS")
		return p.serveCacheMiss(w, r, route, target, cacheKey)
	} else {
		p.cache.Metrics.Bypass(route.Name, bypassReason)
		w.Header().Set(cacheHeader, "BYPASS")
	}
	return p.serveUpstream(w, r, route, target, "", rewritableRoute(route) && info.Kind != "artifact", nil)
}

// rewritesMetadata marks a registry metadata request whose body may be rewritten;
// artifacts are never rewritten and keep the client's encoding negotiation.
func (p *Proxy) serveUpstream(w http.ResponseWriter, r *http.Request, route config.RouteConfig, target, cacheKey string, rewritesMetadata bool, complete func()) (Result, error) {
	if complete == nil {
		complete = func() {}
	}
	complete = sync.OnceFunc(complete)
	storeOwnsCompletion := false
	defer func() {
		if !storeOwnsCompletion {
			complete()
		}
	}()
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		return Result{}, err
	}
	copyRequestHeaders(req.Header, r.Header)
	// Registry metadata is rewritten byte-for-byte to point downloads back at the
	// firewall. A compressed body defeats that silently: pip and uv send gzip,
	// and every wheel then came straight from files.pythonhosted.org. A client
	// that refuses identity still gets it for metadata: RFC 9110 12.5.3 allows
	// disregarding Accept-Encoding, and an unrewritten body would escape the firewall.
	if cacheKey != "" || rewritesMetadata {
		req.Header.Set("Accept-Encoding", "identity")
	}
	if route.UpstreamTokenEnv != "" {
		if token := os.Getenv(route.UpstreamTokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	requestedAt := p.now()
	resp, err := p.do(req, route)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	receivedAt := p.now()
	var npmExpiresAt time.Time
	var npmBypassReason string
	if cacheKey != "" {
		npmExpiresAt, npmBypassReason = p.prepareNPMCacheResponse(resp, route, target, requestedAt, receivedAt)
	}
	// Cloudflare fronts several upstreams (e.g. Maven Central) and now attaches a
	// __cf_bm bot-management cookie to every artifact response, which would otherwise
	// bypass caching through responseBypassReason. Those CDN visitor cookies must
	// never be persisted or replayed to another client, so strip them from the
	// forwarded response whenever every Set-Cookie is a recognised CDN cookie; on a
	// cacheable response this also keeps them out of the stored entry and lets the
	// TTL path store it. This runs for any keyed non-npm response, including ones
	// that then bypass for another reason (non-200, private, redirect) — stripping a
	// CDN visitor cookie there is still correct, and the bypass is unaffected. Any
	// non-CDN Set-Cookie leaves them all in place so the response_set_cookie bypass
	// still protects a genuine session cookie. The npm freshness path handles its
	// own routes above via prepareNPMCacheResponse.
	if cacheKey != "" && route.Ecosystem != "npm" {
		if cookies := resp.Header.Values("Set-Cookie"); len(cookies) != 0 {
			allCDN := true
			for _, value := range cookies {
				if !validCDNCookie(value) {
					allCDN = false
					break
				}
			}
			if allCDN {
				resp.Header.Del("Set-Cookie")
			}
		}
	}
	copyResponseHeaders(w.Header(), resp.Header)
	if p.shouldRewrite(route, resp) {
		if encoding, ok := identityContentEncoding(resp.Header.Values("Content-Encoding")); !ok {
			return Result{}, fmt.Errorf("%w: %s", errEncodedRewriteBody, encoding)
		}
		if cacheKey != "" {
			p.cache.Metrics.Bypass(route.Name, "response_rewrite")
		}
		// The rewrite changes the length and streams, so the upstream length no longer applies.
		w.Header().Del("Content-Length")
		w.WriteHeader(resp.StatusCode)
		return Result{StatusCode: resp.StatusCode}, rewriteStream(w, resp.Body, p.rewriteRules(route))
	}
	if cacheKey != "" {
		responseReason := npmBypassReason
		if responseReason == "" {
			responseReason = p.responseBypassReason(resp, route, target, !npmExpiresAt.IsZero())
		}
		if responseReason == "" {
			storeOwnsCompletion = true
			return p.serveAndStore(w, route, resp, cacheKey, receivedAt, npmExpiresAt, complete)
		} else {
			p.cache.Metrics.Bypass(route.Name, responseReason)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return Result{StatusCode: resp.StatusCode}, err
}

func (p *Proxy) cacheKey(r *http.Request, route config.RouteConfig, info registry.RequestInfo, target string) (string, string) {
	if p.cache.Store == nil {
		return "", "cache_disabled"
	}
	if r.Method != http.MethodGet {
		return "", "method"
	}
	if (info.Kind != "artifact" && !info.Cacheable) || !info.NeedsDecision || info.Package.PURL == "" || info.Package.Name == "" || info.Package.Version == "" {
		return "", "not_exact_artifact"
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return "", "query"
	}
	if r.Header.Get("Range") != "" {
		return "", "range"
	}
	if hasConditionalHeader(r.Header) {
		return "", "conditional"
	}
	if requestDisablesCaching(r.Header) {
		return "", "request_cache_control"
	}
	if r.Body != nil && r.Body != http.NoBody {
		return "", "request_body"
	}
	if !cacheableRequestRepresentation(r.Header) {
		return "", "representation"
	}
	// Entries on an enforcing route may have been fetched through an allowlisted
	// redirect, and carry no record of which origin served them. Binding the key
	// to the policy means revoking an origin's trust orphans anything already
	// stored under the old allowlist instead of serving it until its TTL expires.
	components := []string{http.MethodGet, route.Name, route.Ecosystem, target, "representation-v2", "identity"}
	if route.Ecosystem == "npm" {
		components = append(components, "npm-freshness-v2")
	}
	if fingerprint := redirectPolicyFingerprint(route); fingerprint != "" {
		components = append(components, fingerprint)
	}
	return artifactcache.Key(components...), ""
}

func redirectPolicyFingerprint(route config.RouteConfig) string {
	if !route.EnforceRedirectOrigins {
		return ""
	}
	origins := make([]string, 0, len(route.AllowedRedirectOrigins))
	for _, value := range route.AllowedRedirectOrigins {
		origin, err := config.NormalizeHTTPOrigin(value)
		if err != nil {
			origin = value
		}
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	sum := sha256.Sum256([]byte(strings.Join(origins, "\n")))
	return "redirect-policy-" + hex.EncodeToString(sum[:8])
}

func (p *Proxy) responseBypassReason(resp *http.Response, route config.RouteConfig, target string, freshNPM bool) string {
	if resp.StatusCode != http.StatusOK {
		return "upstream_status"
	}
	if resp.Request != nil && (resp.Request.Context().Value(upstreamRedirectedKey{}) == true || (resp.Request.URL != nil && resp.Request.URL.String() != target)) {
		if !cacheableRedirect(resp, route) {
			return "upstream_redirect"
		}
	}
	if !cacheableResponseVary(resp.Header) {
		return "response_vary"
	}
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		return "response_set_cookie"
	}
	if resp.Header.Get("Content-Range") != "" {
		return "response_content_range"
	}
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return "response_encoding"
	}
	if resp.Uncompressed {
		return "response_encoding"
	}
	if responseDisablesCaching(resp.Header, freshNPM) {
		return "response_cache_control"
	}
	if resp.ContentLength > p.cache.MaxObjectSize {
		return "object_too_large"
	}
	return ""
}

func (p *Proxy) loadCached(r *http.Request, key string) (*stagedEntry, error) {
	ctx, cancel := context.WithTimeout(r.Context(), p.cache.ReadTimeout)
	defer cancel()
	entry, err := p.cache.Store.Get(ctx, key)
	if err != nil {
		if entry.Body != nil {
			_ = entry.Body.Close()
		}
		return nil, err
	}
	if err := artifactcache.ValidateEntry(entry); err != nil {
		_ = entry.Body.Close()
		return nil, err
	}
	if entry.Expired(p.now()) {
		_ = entry.Body.Close()
		return nil, artifactcache.ErrNotFound
	}
	if entry.Size > p.cache.MaxObjectSize {
		_ = entry.Body.Close()
		return nil, errors.Join(artifactcache.ErrInvalidEntry, errObjectTooLarge)
	}
	temporary, err := p.createTemp(p.cache.TempDirectory, "package-firewall-cache-hit-*")
	if err != nil {
		_ = entry.Body.Close()
		return nil, err
	}
	staged := &stagedEntry{
		file:     temporary,
		path:     temporary.Name(),
		headers:  artifactcache.SafeHeaders(entry.Headers),
		size:     entry.Size,
		storedAt: entry.StoredAt,
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = staged.Close()
		}
	}()

	written, checksum, copyErr := copyBounded(ctx, temporary, entry.Body, p.cache.MaxObjectSize)
	closeErr := entry.Body.Close()
	if copyErr != nil || closeErr != nil {
		return nil, errors.Join(copyErr, closeErr)
	}
	if written != entry.Size {
		return nil, errors.Join(artifactcache.ErrInvalidEntry, fmt.Errorf("cached body size %d does not match metadata size %d", written, entry.Size))
	}
	if !strings.EqualFold(checksum, entry.SHA256) {
		return nil, errors.Join(artifactcache.ErrInvalidEntry, fmt.Errorf("cached body checksum %s does not match metadata checksum %s", checksum, entry.SHA256))
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if entry.Expired(p.now()) {
		return nil, artifactcache.ErrNotFound
	}
	cleanup = false
	return staged, nil
}

func serveCached(w http.ResponseWriter, cached *stagedEntry, now time.Time) (Result, error) {
	copyResponseHeaders(w.Header(), agedHeaders(cached.headers, cached.storedAt, now))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", cached.size))
	w.Header().Set(cacheHeader, "HIT")
	w.WriteHeader(http.StatusOK)
	written, err := io.CopyN(w, cached.file, cached.size)
	if err == nil && written != cached.size {
		err = io.ErrUnexpectedEOF
	}
	return Result{StatusCode: http.StatusOK}, err
}

func agedHeaders(headers http.Header, storedAt, now time.Time) http.Header {
	aged := artifactcache.SafeHeaders(headers)
	var age int64
	if value, err := strconv.ParseInt(strings.TrimSpace(aged.Get("Age")), 10, 64); err == nil && value > 0 {
		age = value
	}
	if date, err := http.ParseTime(aged.Get("Date")); err == nil && storedAt.After(date) {
		if apparent := int64(storedAt.Sub(date) / time.Second); apparent > age {
			age = apparent
		}
	}
	if now.After(storedAt) {
		resident := int64(now.Sub(storedAt) / time.Second)
		if age > math.MaxInt64-resident {
			age = math.MaxInt64
		} else {
			age += resident
		}
	}
	aged.Set("Age", strconv.FormatInt(age, 10))
	return aged
}

func (p *Proxy) serveAndStore(w http.ResponseWriter, route config.RouteConfig, resp *http.Response, key string, receivedAt, npmExpiresAt time.Time, complete func()) (Result, error) {
	storeOwnsCompletion := false
	defer func() {
		if !storeOwnsCompletion {
			complete()
		}
	}()
	temporary, err := p.createTemp(p.cache.TempDirectory, "package-firewall-cache-miss-*")
	if err != nil {
		p.recordStoreError(route.Name, err)
		w.WriteHeader(resp.StatusCode)
		_, copyErr := io.Copy(w, resp.Body)
		return Result{StatusCode: resp.StatusCode}, copyErr
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = temporary.Close()
			_ = os.Remove(temporary.Name())
		}
	}()

	spool := newCaptureSpool(temporary, p.cache.MaxObjectSize)
	w.WriteHeader(resp.StatusCode)
	if err := streamAndCapture(w, resp.Body, spool); err != nil {
		return Result{StatusCode: resp.StatusCode}, err
	}
	if spool.err != nil {
		p.recordStoreError(route.Name, spool.err)
		return Result{StatusCode: resp.StatusCode}, nil
	}
	if spool.overflow {
		p.cache.Metrics.Bypass(route.Name, "object_too_large")
		return Result{StatusCode: resp.StatusCode}, nil
	}
	if _, err := temporary.Seek(0, io.SeekStart); err != nil {
		p.recordStoreError(route.Name, err)
		return Result{StatusCode: resp.StatusCode}, nil
	}
	storedAt := p.now()
	headers := artifactcache.SafeHeaders(resp.Header)
	expiresAt := storedAt.Add(p.cache.ArtifactTTL)
	if !npmExpiresAt.IsZero() {
		if !npmExpiresAt.After(storedAt) {
			p.cache.Metrics.Bypass(route.Name, "response_cache_control")
			return Result{StatusCode: resp.StatusCode}, nil
		}
		if npmExpiresAt.Before(expiresAt) {
			expiresAt = npmExpiresAt
		}
		headers = agedHeaders(headers, receivedAt, storedAt)
	}
	if headers.Get("Date") == "" {
		headers.Set("Date", storedAt.UTC().Format(http.TimeFormat))
	}
	request := artifactcache.PutRequest{
		Headers:   headers,
		Body:      temporary,
		SHA256:    spool.checksum(),
		Size:      spool.size,
		StoredAt:  storedAt,
		ExpiresAt: expiresAt,
	}
	temporaryPath := temporary.Name()
	cleanup = false
	storeOwnsCompletion = true
	p.startStore(func() {
		defer complete()
		defer func() {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), p.cache.StoreTimeout)
		defer cancel()
		if err := p.cache.Store.Put(ctx, key, request); err != nil {
			p.recordStoreError(route.Name, err)
		}
	})
	return Result{StatusCode: resp.StatusCode}, nil
}

func (p *Proxy) recordStoreError(route string, err error) {
	p.cache.Metrics.StoreError(route)
	p.logger.Warn("artifact_cache_store_failed", "route", route, "error", err)
}

func copyBounded(ctx context.Context, dst io.Writer, src io.Reader, maximum int64) (int64, string, error) {
	hasher := sha256.New()
	writer := io.MultiWriter(dst, hasher)
	buffer := make([]byte, 32<<10)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, hex.EncodeToString(hasher.Sum(nil)), err
		}
		read, readErr := src.Read(buffer)
		if err := ctx.Err(); err != nil {
			return written, hex.EncodeToString(hasher.Sum(nil)), err
		}
		if read > 0 {
			allowed := int64(read)
			if remaining := maximum - written; allowed > remaining {
				allowed = remaining
			}
			if allowed > 0 {
				count, writeErr := writer.Write(buffer[:allowed])
				written += int64(count)
				if writeErr != nil {
					return written, hex.EncodeToString(hasher.Sum(nil)), writeErr
				}
				if int64(count) != allowed {
					return written, hex.EncodeToString(hasher.Sum(nil)), io.ErrShortWrite
				}
			}
			if allowed < int64(read) {
				return written, hex.EncodeToString(hasher.Sum(nil)), errObjectTooLarge
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, hex.EncodeToString(hasher.Sum(nil)), nil
			}
			return written, hex.EncodeToString(hasher.Sum(nil)), readErr
		}
		if read == 0 {
			return written, hex.EncodeToString(hasher.Sum(nil)), io.ErrNoProgress
		}
	}
}

type captureSpool struct {
	writer   io.Writer
	hasher   hash.Hash
	maximum  int64
	size     int64
	overflow bool
	err      error
}

func newCaptureSpool(writer io.Writer, maximum int64) *captureSpool {
	return &captureSpool{writer: writer, hasher: sha256.New(), maximum: maximum}
}

func (s *captureSpool) capture(body []byte) {
	if s.err != nil || s.overflow || len(body) == 0 {
		return
	}
	allowed := int64(len(body))
	if remaining := s.maximum - s.size; allowed > remaining {
		allowed = remaining
	}
	if allowed > 0 {
		written, err := s.writer.Write(body[:allowed])
		if written > 0 {
			_, _ = s.hasher.Write(body[:written])
			s.size += int64(written)
		}
		if err != nil {
			s.err = err
			return
		}
		if int64(written) != allowed {
			s.err = io.ErrShortWrite
			return
		}
	}
	if allowed < int64(len(body)) {
		s.overflow = true
	}
}

func (s *captureSpool) checksum() string {
	return hex.EncodeToString(s.hasher.Sum(nil))
}

func streamAndCapture(dst io.Writer, src io.Reader, spool *captureSpool) error {
	buffer := make([]byte, 32<<10)
	for {
		read, readErr := src.Read(buffer)
		if read > 0 {
			written, writeErr := dst.Write(buffer[:read])
			if written > 0 {
				spool.capture(buffer[:written])
			}
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
}

type stagedEntry struct {
	file     *os.File
	path     string
	headers  http.Header
	size     int64
	storedAt time.Time
}

func createCacheTemp(directory, pattern string) (*os.File, error) {
	if directory != "" {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, err
		}
	}
	return os.CreateTemp(directory, pattern)
}

func (e *stagedEntry) Close() error {
	return errors.Join(e.file.Close(), os.Remove(e.path))
}

func hasConditionalHeader(headers http.Header) bool {
	for _, name := range []string{"If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since"} {
		if headers.Get(name) != "" {
			return true
		}
	}
	return false
}

func requestDisablesCaching(headers http.Header) bool {
	return strings.TrimSpace(strings.Join(headers.Values("Cache-Control"), ",")) != "" ||
		strings.TrimSpace(headers.Get("Pragma")) != ""
}

func responseDisablesCaching(headers http.Header, freshNPM bool) bool {
	return hasCacheDirective(headers.Values("Cache-Control"), "no-cache", "no-store", "private") ||
		(!freshNPM && hasCacheDirective(headers.Values("Cache-Control"), "must-revalidate", "proxy-revalidate", "max-age=0", "s-maxage=0")) ||
		hasCacheDirective(headers.Values("Pragma"), "no-cache")
}

func hasCacheDirective(values []string, directives ...string) bool {
	wanted := make(map[string]struct{}, len(directives))
	for _, directive := range directives {
		wanted[directive] = struct{}{}
	}
	for _, value := range values {
		for _, part := range strings.Split(strings.ToLower(value), ",") {
			part = strings.TrimSpace(part)
			if _, ok := wanted[part]; ok {
				return true
			}
			for directive := range wanted {
				if strings.HasPrefix(part, directive+"=") {
					return true
				}
			}
		}
	}
	return false
}

func cacheableRequestRepresentation(headers http.Header) bool {
	for _, name := range []string{"Accept-Charset", "Accept-Language", "A-IM", "Cookie", "Origin", "Prefer", "Want-Digest"} {
		if headers.Get(name) != "" {
			return false
		}
	}
	return identityEncodingAccepted(headers.Values("Accept-Encoding"))
}

func identityEncodingAccepted(values []string) bool {
	raw := strings.TrimSpace(strings.Join(values, ","))
	if raw == "" {
		return true
	}
	identitySeen := false
	identityAccepted := false
	wildcardSeen := false
	wildcardAccepted := false
	for _, item := range strings.Split(raw, ",") {
		parts := strings.Split(item, ";")
		coding := strings.ToLower(strings.TrimSpace(parts[0]))
		if coding == "" {
			return false
		}
		accepted, valid := encodingQualityAccepted(parts[1:])
		if !valid {
			return false
		}
		switch coding {
		case "identity":
			identitySeen = true
			identityAccepted = identityAccepted || accepted
		case "*":
			wildcardSeen = true
			wildcardAccepted = wildcardAccepted || accepted
		}
	}
	if identitySeen {
		return identityAccepted
	}
	return !wildcardSeen || wildcardAccepted
}

func encodingQualityAccepted(parameters []string) (bool, bool) {
	if len(parameters) == 0 {
		return true, true
	}
	if len(parameters) != 1 {
		return false, false
	}
	name, value, found := strings.Cut(parameters[0], "=")
	if !found || !strings.EqualFold(strings.TrimSpace(name), "q") {
		return false, false
	}
	return qualityAccepted(strings.TrimSpace(value))
}

func qualityAccepted(value string) (bool, bool) {
	whole, fraction, hasFraction := strings.Cut(value, ".")
	if !hasFraction {
		fraction = ""
	}
	if len(fraction) > 3 {
		return false, false
	}
	for _, digit := range fraction {
		if digit < '0' || digit > '9' {
			return false, false
		}
	}
	switch whole {
	case "0":
		return strings.ContainsAny(fraction, "123456789"), true
	case "1":
		return !strings.ContainsAny(fraction, "123456789"), true
	default:
		return false, false
	}
}

func cacheableResponseVary(headers http.Header) bool {
	for _, value := range headers.Values("Vary") {
		for _, name := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "", "accept-encoding":
			default:
				return false
			}
		}
	}
	return true
}

type upstreamRedirectedKey struct{}

func (p *Proxy) doOnce(request *http.Request, route config.RouteConfig) (*http.Response, error) {
	checkRedirect, err := upstreamRedirectPolicy(
		route.EnforceRedirectOrigins,
		route.AllowedRedirectOrigins,
		func(initialOrigin, redirectOrigin string) {
			p.logger.Info(
				"upstream_cross_origin_redirect",
				"route", route.Name,
				"initial_origin", initialOrigin,
				"redirect_origin", redirectOrigin,
				"enforced", route.EnforceRedirectOrigins,
			)
		},
	)
	if err != nil {
		return nil, err
	}
	client := *p.client
	configuredCheck := client.CheckRedirect
	redirected := false
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		redirected = true
		if err := checkRedirect(request, via); err != nil {
			return err
		}
		if configuredCheck != nil {
			if err := configuredCheck(request, via); err != nil {
				if errors.Is(err, http.ErrUseLastResponse) {
					return errors.New("configured redirect policy stopped redirect")
				}
				return err
			}
		}
		return nil
	}
	// CheckRedirect only sees requests, so the hop responses -- and any cache
	// directives steering them -- are visible only from the transport.
	hops := &redirectHops{}
	client.Transport = recordRedirectHops(client.Transport, hops)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if err := validateReturnedRedirect(request, response, checkRedirect); err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	if redirected && response.Request != nil {
		ctx := context.WithValue(response.Request.Context(), upstreamRedirectedKey{}, true)
		ctx = context.WithValue(ctx, upstreamRedirectHopsKey{}, hops.uncacheable())
		response.Request = response.Request.WithContext(ctx)
	}
	return response, nil
}

type upstreamRedirectHopsKey struct{}

type redirectHops struct {
	mu           sync.Mutex
	uncacheableH bool
}

// uncacheable reports whether any followed hop declared directives that make the
// artifact it selected unsafe to store under the originally requested key.
func (h *redirectHops) uncacheable() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.uncacheableH
}

func (h *redirectHops) observe(resp *http.Response) {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return
	}
	// cacheableResponseVary, not "any Vary at all": the Gradle Plugin Portal sends
	// Vary: accept-encoding on the hop that reaches Maven Central, and rejecting
	// that made every plugin marker permanently uncacheable. Accept-Encoding is
	// pinned to identity for anything cacheable and is part of the key, so varying
	// on it selects nothing the key does not already carry.
	control := strings.ToLower(resp.Header.Get("Cache-Control"))
	if cacheableResponseVary(resp.Header) && !strings.Contains(control, "no-store") && !strings.Contains(control, "private") {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.uncacheableH = true
}

type redirectHopRecorder struct {
	base http.RoundTripper
	hops *redirectHops
}

func (r redirectHopRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(request)
	if err == nil && response != nil {
		r.hops.observe(response)
	}
	return response, err
}

func recordRedirectHops(base http.RoundTripper, hops *redirectHops) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return redirectHopRecorder{base: base, hops: hops}
}

// cacheableRedirect reports whether a redirected response may be stored.
//
// upstreamRedirectPolicy already decides whether a redirect may be *followed*,
// against a per-route origin allowlist, and the bytes it returns are already
// served to the client. Refusing to also cache them buys nothing when the
// destination is one the route explicitly trusts: the Gradle Plugin Portal
// serves Central-published plugin markers by redirecting to
// repo.maven.apache.org, which that route allowlists, so those artifacts could
// never be cached and a prewarm second pass could never see them as a HIT.
//
// Only a redirect to an origin the route enforces an allowlist for is cacheable.
// A route that does not enforce origins has no allowlist to appeal to, and a
// same-origin redirect is deliberately excluded: npm's CDN bounces a tarball
// request through an unrelated path on the same host, so caching that under the
// requested key would store bytes fetched from somewhere else and persist the
// visitor cookies that come with them.
func cacheableRedirect(resp *http.Response, route config.RouteConfig) bool {
	if resp.Request == nil || !route.EnforceRedirectOrigins {
		return false
	}
	// A hop that declares Vary or no-store may have selected this artifact from a
	// forwarded header the cache key does not carry, so it must not be replayed.
	if resp.Request.Context().Value(upstreamRedirectHopsKey{}) == true {
		return false
	}
	finalOrigin, err := requestOrigin(resp.Request.URL)
	if err != nil {
		return false
	}
	// Checked before the allowlist, not after: a route may redundantly list its
	// own upstream origin, and that must not make a same-origin bounce cacheable.
	upstream, err := upstreamOrigin(route.UpstreamURL)
	if err != nil || finalOrigin == upstream {
		return false
	}
	for _, value := range route.AllowedRedirectOrigins {
		allowed, err := config.NormalizeHTTPOrigin(value)
		if err != nil {
			continue
		}
		if allowed == finalOrigin {
			return true
		}
	}
	return false
}

func upstreamOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	return requestOrigin(parsed)
}

func upstreamRedirectPolicy(enforce bool, allowedOrigins []string, observe func(string, string)) (func(*http.Request, []*http.Request) error, error) {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, value := range allowedOrigins {
		origin, err := config.NormalizeHTTPOrigin(value)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed redirect origin %q: %w", value, err)
		}
		allowed[origin] = struct{}{}
	}
	return func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return errors.Join(errUnsafeUpstreamRedirect, errors.New("initial upstream request is missing"))
		}
		if len(via) >= maxUpstreamRedirects {
			return fmt.Errorf("%w after %d redirects", errUpstreamRedirectLimit, len(via))
		}
		initialOrigin, err := requestOrigin(via[0].URL)
		if err != nil {
			return errors.Join(errUnsafeUpstreamRedirect, err)
		}
		redirectOrigin, err := requestOrigin(request.URL)
		if err != nil {
			return errors.Join(errUnsafeUpstreamRedirect, err)
		}
		if redirectOrigin == initialOrigin {
			return nil
		}
		if observe != nil {
			observe(initialOrigin, redirectOrigin)
		}
		if !enforce {
			return nil
		}
		if _, ok := allowed[redirectOrigin]; ok {
			return nil
		}
		return fmt.Errorf("%w from %q to %q", errUnsafeUpstreamRedirect, initialOrigin, redirectOrigin)
	}, nil
}

func validateReturnedRedirect(request *http.Request, response *http.Response, checkRedirect func(*http.Request, []*http.Request) error) error {
	if response.StatusCode != http.StatusTemporaryRedirect && response.StatusCode != http.StatusPermanentRedirect {
		return nil
	}
	location, err := response.Location()
	if errors.Is(err, http.ErrNoLocation) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("invalid upstream redirect location: %w", err)
	}
	redirected := &http.Request{URL: location}
	if err := checkRedirect(redirected, []*http.Request{request}); err != nil {
		return err
	}
	if request.Body != nil && request.Body != http.NoBody && request.GetBody == nil {
		return errUnreplayableBodyRedirect
	}
	return nil
}

func requestOrigin(value *url.URL) (string, error) {
	if value == nil {
		return "", errors.New("redirect URL is missing")
	}
	if value.User != nil {
		return "", errors.New("redirect URL must not include user information")
	}
	origin := (&url.URL{Scheme: value.Scheme, Host: value.Host}).String()
	return config.NormalizeHTTPOrigin(origin)
}

func upstreamURL(route config.RouteConfig, info registry.RequestInfo) (string, error) {
	raw := route.UpstreamURL
	if info.FileUpstream && route.FileUpstreamURL != "" {
		raw = route.FileUpstreamURL
	}
	base, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	prefix := strings.TrimRight(base.Path, "/")
	path, err := safeUpstreamPath(info.UpstreamPath)
	if err != nil {
		return "", err
	}
	base.Path = prefix + path
	return base.String(), nil
}

func withRequestQuery(target string, requestURL *url.URL) (string, error) {
	if requestURL == nil || (requestURL.RawQuery == "" && !requestURL.ForceQuery) {
		return target, nil
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	if parsed.RawQuery == "" {
		parsed.RawQuery = requestURL.RawQuery
	} else if requestURL.RawQuery != "" {
		parsed.RawQuery += "&" + requestURL.RawQuery
	}
	parsed.ForceQuery = parsed.ForceQuery || requestURL.ForceQuery
	return parsed.String(), nil
}

func safeUpstreamPath(value string) (string, error) {
	path := "/" + strings.TrimLeft(value, "/")
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return "", err
		}
		if part == "." || part == ".." || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, `/\`) {
			return "", fmt.Errorf("upstream path contains unsafe segment %q", part)
		}
	}
	return path, nil
}

// identityContentEncoding reports whether every Content-Encoding field, split on
// commas, is empty or identity. Header.Get reads only the first field, which let
// "identity" followed by a separate "gzip" field through.
func identityContentEncoding(values []string) (string, bool) {
	for _, value := range values {
		for _, coding := range strings.Split(value, ",") {
			coding = strings.TrimSpace(coding)
			if coding != "" && !strings.EqualFold(coding, "identity") {
				return strings.Join(values, ", "), false
			}
		}
	}
	return "", true
}

func rewritableRoute(route config.RouteConfig) bool {
	return route.Ecosystem == "npm" || route.Ecosystem == "pypi"
}

func (p *Proxy) shouldRewrite(route config.RouteConfig, resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	// pnpm, Yarn and npm ask for the abbreviated packument, served as
	// application/vnd.npm.install-v1+json; matching only application/json left
	// its tarball URLs on registry.npmjs.org.
	if route.Ecosystem == "npm" && (strings.Contains(contentType, "application/json") || strings.Contains(contentType, "application/vnd.npm.install-v1+json")) {
		return true
	}
	if route.Ecosystem == "pypi" && (strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/vnd.pypi.simple") || strings.Contains(contentType, "application/json")) {
		return true
	}
	return false
}

func copyRequestHeaders(dst, src http.Header) {
	copyHeaders(dst, src, sensitiveRequestHeader)
}

func copyResponseHeaders(dst, src http.Header) {
	copyHeaders(dst, src, func(header string) bool {
		return strings.EqualFold(header, cacheHeader)
	})
}

func copyHeaders(dst, src http.Header, skip func(string) bool) {
	for key, values := range src {
		if hopByHop(key) || skip(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func sensitiveRequestHeader(header string) bool {
	switch strings.ToLower(header) {
	case "authorization",
		"proxy-authorization",
		"cookie",
		"cf-access-jwt-assertion",
		"cf-access-authenticated-user-email",
		"x-amzn-oidc-data",
		"x-amzn-oidc-accesstoken",
		"x-auth-request-access-token",
		"x-auth-request-email",
		"x-auth-request-user",
		"x-forwarded-access-token",
		"x-forwarded-email",
		"x-forwarded-user":
		return true
	default:
		return false
	}
}

func hopByHop(header string) bool {
	switch strings.ToLower(header) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

type noopCacheMetrics struct{}

func (noopCacheMetrics) Hit(string)            {}
func (noopCacheMetrics) Miss(string)           {}
func (noopCacheMetrics) StoreError(string)     {}
func (noopCacheMetrics) ReadError(string)      {}
func (noopCacheMetrics) Bypass(string, string) {}
