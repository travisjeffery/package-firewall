package proxy

import (
	"bytes"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/travisjeffery/package-firewall/internal/artifactcache"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/coordination"
	"github.com/travisjeffery/package-firewall/internal/registry"
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
	return p.serveUpstream(w, r, route, target, "", nil)
}

func (p *Proxy) serveUpstream(w http.ResponseWriter, r *http.Request, route config.RouteConfig, target, cacheKey string, complete func()) (Result, error) {
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
	if cacheKey != "" {
		req.Header.Set("Accept-Encoding", "identity")
	}
	if route.UpstreamTokenEnv != "" {
		if token := os.Getenv(route.UpstreamTokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := p.do(req, route)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
	if p.shouldRewrite(route, resp) {
		if cacheKey != "" {
			p.cache.Metrics.Bypass(route.Name, "response_rewrite")
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
		if err != nil {
			return Result{}, err
		}
		body = p.rewriteBody(route, body)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(resp.StatusCode)
		_, err = io.Copy(w, bytes.NewReader(body))
		return Result{StatusCode: resp.StatusCode}, err
	}
	if cacheKey != "" {
		if responseReason := p.responseBypassReason(resp, target); responseReason == "" {
			storeOwnsCompletion = true
			return p.serveAndStore(w, route, resp, cacheKey, complete)
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
	if info.Kind != "artifact" || !info.NeedsDecision || info.Package.PURL == "" || info.Package.Name == "" || info.Package.Version == "" {
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
	representation, cacheable := cacheRepresentation(r.Header)
	if !cacheable {
		return "", "representation"
	}
	return artifactcache.Key(http.MethodGet, route.Name, route.Ecosystem, target, "representation-v1", representation, "identity"), ""
}

func (p *Proxy) responseBypassReason(resp *http.Response, target string) string {
	if resp.StatusCode != http.StatusOK {
		return "upstream_status"
	}
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.String() != target {
		return "upstream_redirect"
	}
	if !cacheableResponseVary(resp.Header) {
		return "response_vary"
	}
	if resp.Header.Get("Set-Cookie") != "" {
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
	if responseDisablesCaching(resp.Header) {
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

func (p *Proxy) serveAndStore(w http.ResponseWriter, route config.RouteConfig, resp *http.Response, key string, complete func()) (Result, error) {
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
	if headers.Get("Date") == "" {
		headers.Set("Date", storedAt.UTC().Format(http.TimeFormat))
	}
	request := artifactcache.PutRequest{
		Headers:   headers,
		Body:      temporary,
		SHA256:    spool.checksum(),
		Size:      spool.size,
		StoredAt:  storedAt,
		ExpiresAt: storedAt.Add(p.cache.ArtifactTTL),
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

func responseDisablesCaching(headers http.Header) bool {
	return hasCacheDirective(headers.Values("Cache-Control"), "no-cache", "no-store", "private", "max-age=0", "s-maxage=0", "must-revalidate", "proxy-revalidate") ||
		strings.EqualFold(strings.TrimSpace(headers.Get("Pragma")), "no-cache")
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

func cacheRepresentation(headers http.Header) (string, bool) {
	for _, name := range []string{"Accept-Charset", "Accept-Language", "A-IM", "Cookie", "Origin", "Prefer", "Want-Digest"} {
		if headers.Get(name) != "" {
			return "", false
		}
	}
	if !identityEncodingAccepted(headers.Values("Accept-Encoding")) {
		return "", false
	}
	return strings.TrimSpace(strings.Join(headers.Values("Accept"), ",")), true
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
			case "", "accept", "accept-encoding":
			default:
				return false
			}
		}
	}
	return true
}

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
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
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
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	if err := validateReturnedRedirect(request, response, checkRedirect); err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	return response, nil
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

func (p *Proxy) shouldRewrite(route config.RouteConfig, resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	if route.Ecosystem == "npm" && strings.Contains(contentType, "application/json") {
		return true
	}
	if route.Ecosystem == "pypi" && (strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/vnd.pypi.simple") || strings.Contains(contentType, "application/json")) {
		return true
	}
	return false
}

func (p *Proxy) rewriteBody(route config.RouteConfig, body []byte) []byte {
	switch route.Ecosystem {
	case "npm":
		return bytes.ReplaceAll(body, []byte("https://registry.npmjs.org/"), []byte(p.baseURL+strings.TrimRight(route.PathPrefix, "/")+"/"))
	case "pypi":
		body = bytes.ReplaceAll(body, []byte("https://files.pythonhosted.org/"), []byte(p.baseURL+strings.TrimRight(route.PathPrefix, "/")+"/files/"))
		body = bytes.ReplaceAll(body, []byte("http://files.pythonhosted.org/"), []byte(p.baseURL+strings.TrimRight(route.PathPrefix, "/")+"/files/"))
		return body
	default:
		return body
	}
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
