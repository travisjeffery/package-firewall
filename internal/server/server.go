package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/travisjeffery/package-firewall/internal/audit"
	"github.com/travisjeffery/package-firewall/internal/cachemetrics"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/coordination"
	"github.com/travisjeffery/package-firewall/internal/explain"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/proxy"
	"github.com/travisjeffery/package-firewall/internal/registry"
	"github.com/travisjeffery/package-firewall/internal/release"
)

type Server struct {
	cfg         config.Config
	policy      *policy.Engine
	intel       intel.Provider
	release     publishTimes
	proxy       *proxy.Proxy
	metrics     *cachemetrics.Metrics
	audit       *audit.Logger
	logger      *slog.Logger
	routes      []config.RouteConfig
	bearer      string
	basicUser   string
	basicPass   string
	authReady   bool
	explainRate *tokenBucket
}

const (
	authMetricsRoute      = "__auth__"
	unmatchedMetricsRoute = "__unmatched__"
)

type publishTimes interface {
	PublishedAt(ctx context.Context, route registry.Route, info registry.RequestInfo) (time.Time, error)
}

type RuntimeConfig struct {
	Cache       proxy.CacheConfig
	Coordinator coordination.Coordinator
}

func New(cfg config.Config, policyEngine *policy.Engine, provider intel.Provider, runtimeConfigs ...RuntimeConfig) *Server {
	routes := append([]config.RouteConfig(nil), cfg.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
	})
	if provider == nil {
		provider = intel.NoopProvider{}
	}
	metrics := cachemetrics.New()
	runtimeConfig := RuntimeConfig{}
	if len(runtimeConfigs) > 0 {
		runtimeConfig = runtimeConfigs[0]
	}
	runtimeConfig.Cache.Metrics = metrics
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	upstreamClient := proxy.NewHTTPClient(cfg.Upstream.RequestTimeout.Std(), cfg.Upstream.ResponseHeaderTimeout.Std())
	bearer, bearerOK := secretFromEnv(cfg.Auth.BearerTokenEnv)
	basicUser, basicUserOK := secretFromEnv(cfg.Auth.BasicUsernameEnv)
	basicPass, basicPassOK := secretFromEnv(cfg.Auth.BasicPasswordEnv)
	return &Server{
		cfg:     cfg,
		policy:  policyEngine,
		intel:   provider,
		release: release.NewResolver(upstreamClient),
		proxy: proxy.New(
			cfg.Server.PublicBaseURL,
			proxy.WithHTTPClient(upstreamClient),
			proxy.WithCache(runtimeConfig.Cache),
			proxy.WithCoordination(proxy.CoordinationConfig{
				Coordinator:   runtimeConfig.Coordinator,
				LeaseDuration: cfg.Coordination.LeaseDuration.Std(),
				PollInterval:  cfg.Coordination.PollInterval.Std(),
			}),
			proxy.WithUpstreamProtection(proxy.UpstreamProtectionConfig{
				MaxConcurrentPerRegistry: cfg.Upstream.MaxConcurrentPerRegistry,
				QueueTimeout:             cfg.Upstream.QueueTimeout.Std(),
				RateLimitRetries:         cfg.Upstream.RateLimitRetries,
				MaxRetryAfter:            cfg.Upstream.MaxRetryAfter.Std(),
			}),
			proxy.WithLogger(logger),
		),
		metrics:     metrics,
		audit:       audit.New(),
		logger:      logger,
		routes:      routes,
		bearer:      bearer,
		basicUser:   basicUser,
		basicPass:   basicPass,
		authReady:   bearerOK && basicUserOK && basicPassOK,
		explainRate: newTokenBucket(explainRatePerSecond, explainBurst),
	}
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:         s.cfg.Server.ListenAddr,
		Handler:      s.routesHandler(),
		ReadTimeout:  s.cfg.Server.ReadTimeout.Std(),
		WriteTimeout: s.cfg.Server.WriteTimeout.Std(),
	}
}

func (s *Server) routesHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.Handle("/metrics", s.metrics.Handler())
	mux.HandleFunc("/explain", s.handleExplain)
	mux.HandleFunc("/", s.handle)
	return mux
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	w.Header().Set("X-Request-ID", requestID)
	route, matched := s.matchRoute(r.URL.Path)
	if !matched {
		route, matched = s.matchNPMTarballFallback(r.URL.Path)
	}
	// Routing runs before authentication so a route can opt out of it, but an
	// unmatched path still authenticates first: answering 404 to an anonymous
	// caller would disclose which prefixes this server serves. Matched-and-not-
	// anonymous and unmatched therefore behave exactly as they did when the
	// credential check came first.
	if !matched || !route.AllowAnonymous {
		if !s.authorized(r) {
			s.addAuthenticationChallenges(w.Header())
			writeJSON(w, http.StatusUnauthorized, errorBody("unauthorized", "missing or invalid package firewall credentials", requestID))
			s.metrics.Request(authMetricsRoute, http.StatusUnauthorized)
			return
		}
	}
	if !matched {
		writeJSON(w, http.StatusNotFound, errorBody("not_found", "no package firewall route matched this path", requestID))
		s.metrics.Request(unmatchedMetricsRoute, http.StatusNotFound)
		return
	}
	info := registry.Identify(toRegistryRoute(route), r.URL.Path)
	decision := s.decide(r.Context(), route, info)
	event := audit.FromDecision(r, route.Name, info.Package, requestID, decision)
	if decision.Action == policy.ActionBlock {
		s.audit.Log(event)
		s.writeBlocked(w, explain.New(info.Package, decision, requestID, s.cfg.Decision.ExceptionsURL))
		s.metrics.Request(route.Name, http.StatusForbidden)
		return
	}
	result, err := s.proxy.Serve(w, r, route, info)
	event.UpstreamStatus = result.StatusCode
	if err != nil {
		metricStatus := proxyErrorStatus(err)
		event.Error = err.Error()
		if result.StatusCode == 0 && !errors.Is(err, context.Canceled) {
			status, code, message := upstreamErrorResponse(err)
			event.UpstreamStatus = status
			clear(w.Header())
			w.Header().Set("X-Request-ID", requestID)
			writeJSON(w, status, errorBody(code, message, requestID))
		}
		if event.UpstreamStatus == 0 {
			event.UpstreamStatus = 499
		}
		s.metrics.Request(route.Name, metricStatus)
		s.audit.Log(event)
		// Only a cancellation that came from the client is ordinary traffic. Package managers
		// abort parallel fetches constantly -- nearly every error line in a busy period
		// -- and at ERROR they bury real upstream failures. But cache-fill coordination also
		// cancels a context derived from this request when a lease renewal fails, and the
		// client is still connected for that one. Checking the request context tells the two
		// apart; the 499 status and the audit event record either way.
		if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
			s.logger.Debug("proxy_client_disconnected", "request_id", requestID)
		} else {
			s.logger.Error("proxy_failed", "request_id", requestID, "error", err)
		}
		// The status line already went out, so the client holds a short body. Returning
		// would let net/http end a chunked body as if it were complete, and a cut-off
		// packument then reads as a whole one; aborting resets the connection instead.
		if result.StatusCode != 0 {
			panic(http.ErrAbortHandler)
		}
		return
	}
	s.metrics.Request(route.Name, result.StatusCode)
	s.audit.Log(event)
}

const (
	maxBlockHeaderBytes = 1024
	// A CI job explains each blocked URL from its log, so bursts are normal; the
	// limit only stops one caller from turning /explain into an OSV query pump.
	explainRatePerSecond = 10
	explainBurst         = 50
)

func (s *Server) writeBlocked(w http.ResponseWriter, e explain.Explanation) {
	w.Header().Set("X-Package-Firewall-Reason", explain.HeaderValue(e.Message, maxBlockHeaderBytes))
	w.Header().Set("X-Package-Firewall-Request-Id", e.RequestID)
	if e.Advisory != nil {
		w.Header().Set("X-Package-Firewall-Advisory", explain.HeaderValue(strings.Join(append([]string{e.Advisory.ID}, e.Advisory.Aliases...), ","), maxBlockHeaderBytes))
	}
	// npm prints the body's "error" field after the status line, so it carries the
	// whole message; "code" keeps a stable value for scripts that matched "blocked".
	writeJSON(w, http.StatusForbidden, map[string]any{
		"error":       e.Message,
		"code":        "blocked",
		"request_id":  e.RequestID,
		"purl":        e.PURL,
		"reason":      e.Reason,
		"rule":        e.Rule,
		"explanation": e,
	})
}

// handleExplain answers "why was this blocked?" for clients that print neither
// the body nor the headers of a 403, which is every client except npm. It
// re-runs the same decision for a URL the client failed on, or for a purl.
func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	w.Header().Set("X-Request-ID", requestID)
	route, info, anonymous, targetErr := s.explainTarget(r.URL.Query())
	// A URL on an anonymous route is explained without credentials, as the proxy
	// serves it; anything else, including an invalid target, authenticates first
	// so an anonymous caller learns nothing about which routes exist.
	if !(targetErr == nil && anonymous) && !s.authorized(r) {
		s.addAuthenticationChallenges(w.Header())
		writeJSON(w, http.StatusUnauthorized, errorBody("unauthorized", "missing or invalid package firewall credentials", requestID))
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("method_not_allowed", "use GET", requestID))
		return
	}
	if !s.explainRate.allow() {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, errorBody("rate_limited", "too many explain requests", requestID))
		return
	}
	if targetErr != nil {
		writeJSON(w, http.StatusBadRequest, errorBody("bad_request", targetErr.Error(), requestID))
		return
	}
	if !info.NeedsDecision {
		writeJSON(w, http.StatusBadRequest, errorBody("not_an_artifact", "the URL is registry metadata, which the firewall does not block", requestID))
		return
	}
	e := explain.New(info.Package, s.decide(r.Context(), route, info), requestID, s.cfg.Decision.ExceptionsURL)
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, e.Message)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) explainTarget(query url.Values) (config.RouteConfig, registry.RequestInfo, bool, error) {
	if raw := query.Get("purl"); raw != "" {
		pkg, err := registry.PackageFromPURL(raw)
		if err != nil {
			return config.RouteConfig{}, registry.RequestInfo{}, false, err
		}
		route, _ := s.routeForEcosystem(pkg.Ecosystem)
		return route, registry.RequestInfo{Package: pkg, Kind: "artifact", NeedsDecision: true}, false, nil
	}
	raw := query.Get("url")
	if raw == "" {
		return config.RouteConfig{}, registry.RequestInfo{}, false, errors.New("pass url=<the URL the package manager failed on> or purl=<package URL>")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return config.RouteConfig{}, registry.RequestInfo{}, false, fmt.Errorf("invalid url: %w", err)
	}
	route, matched := s.matchRoute(parsed.Path)
	if !matched {
		route, matched = s.matchNPMTarballFallback(parsed.Path)
	}
	if !matched {
		return config.RouteConfig{}, registry.RequestInfo{}, false, errors.New("no package firewall route matches the url path")
	}
	return route, registry.Identify(toRegistryRoute(route), parsed.Path), route.AllowAnonymous, nil
}

// A purl names no route, so its publish time comes from the first route that
// proxies its ecosystem.
func (s *Server) routeForEcosystem(ecosystem string) (config.RouteConfig, bool) {
	for _, route := range s.cfg.Routes {
		if route.Ecosystem == ecosystem {
			return route, true
		}
	}
	return config.RouteConfig{}, false
}

func proxyErrorStatus(err error) int {
	if errors.Is(err, context.Canceled) {
		return 499
	}
	status, _, _ := upstreamErrorResponse(err)
	return status
}

func (s *Server) addAuthenticationChallenges(header http.Header) {
	if s.cfg.Auth.BasicUsernameEnv != "" || s.cfg.Auth.BasicPasswordEnv != "" {
		header.Add("WWW-Authenticate", `Basic realm="package-firewall"`)
	}
	if s.cfg.Auth.BearerTokenEnv != "" {
		header.Add("WWW-Authenticate", `Bearer realm="package-firewall"`)
	}
}

func upstreamErrorResponse(err error) (int, string, string) {
	if errors.Is(err, proxy.ErrUpstreamQueueTimeout) {
		return http.StatusServiceUnavailable, "upstream_busy", "upstream request queue is full"
	}
	var timeoutError net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeoutError) && timeoutError.Timeout()) {
		return http.StatusGatewayTimeout, "upstream_timeout", "upstream request timed out"
	}
	return http.StatusBadGateway, "upstream_error", "upstream request failed"
}

func (s *Server) decide(ctx context.Context, route config.RouteConfig, info registry.RequestInfo) policy.Decision {
	if !info.NeedsDecision {
		return policy.Decision{Action: policy.ActionAllow, Reason: "metadata request"}
	}
	policyDecision := s.policy.Evaluate(info.Package)
	// The publish time costs an upstream lookup, so it is fetched only when the
	// cooldown is the one check left that could still block.
	if policyDecision.Action == policy.ActionAllow && policyDecision.MatchedRule == "" && s.policy.CooldownEnabled() && info.Package.PublishedAt.IsZero() {
		published, err := s.release.PublishedAt(ctx, toRegistryRoute(route), info)
		if err != nil {
			return s.lookupFailed("release date", err)
		}
		info.Package.PublishedAt = published
		policyDecision = s.policy.Evaluate(info.Package)
	}
	switch policyDecision.Action {
	case policy.ActionBlock, policy.ActionWarn, policy.ActionMonitor:
		return policyDecision
	case policy.ActionAllow:
		if policyDecision.MatchedRule != "" {
			return policyDecision
		}
	case policy.ActionUnknown:
		if s.cfg.Decision.FailOpenUnknownPackage {
			return policy.Decision{Action: policy.ActionWarn, Reason: "unknown package allowed by fail_open_unknown_package", Kind: policy.KindUnknownPackage}
		}
		return policy.Decision{Action: policy.ActionBlock, Reason: "unknown package blocked by fail_open_unknown_package=false", Kind: policy.KindUnknownPackage}
	}
	if info.SkipVulnerabilityCheck {
		return policy.Decision{Action: policy.ActionAllow, Reason: "metadata request allowed after policy evaluation"}
	}
	result, err := s.intel.Query(ctx, info.Package)
	if err != nil {
		return s.lookupFailed("intel", err)
	}
	intelDecision := intel.Decide(result, policy.Action(s.cfg.Decision.DefaultVulnerabilityAction), s.cfg.Decision.VulnerabilityBlockThreshold)
	if intelDecision.Action == policy.ActionAllow {
		return policy.Decision{Action: policy.ActionAllow, Reason: "policy and intel allowed package"}
	}
	return intelDecision
}

func (s *Server) lookupFailed(what string, err error) policy.Decision {
	if s.cfg.Decision.FailOpenIntelErrors {
		return policy.Decision{Action: policy.ActionWarn, Reason: what + " error allowed by fail_open_intel_errors: " + err.Error(), Kind: policy.KindIntelError}
	}
	return policy.Decision{Action: policy.ActionBlock, Reason: what + " error blocked by fail_open_intel_errors=false: " + err.Error(), Kind: policy.KindIntelError}
}

func (s *Server) matchRoute(path string) (config.RouteConfig, bool) {
	for _, route := range s.routes {
		if strings.HasPrefix(path, route.PathPrefix) {
			return route, true
		}
	}
	return config.RouteConfig{}, false
}

func (s *Server) matchNPMTarballFallback(path string) (config.RouteConfig, bool) {
	if !strings.Contains(path, "/-/") || !strings.HasSuffix(path, ".tgz") {
		return config.RouteConfig{}, false
	}
	for _, route := range s.routes {
		if route.Ecosystem == "npm" {
			route.PathPrefix = "/"
			return route, true
		}
	}
	return config.RouteConfig{}, false
}

func (s *Server) authorized(r *http.Request) bool {
	if !s.authReady {
		return false
	}
	if s.bearer == "" && s.basicUser == "" && s.basicPass == "" {
		return true
	}
	if s.bearer != "" {
		const prefix = "Bearer "
		header := r.Header.Get("Authorization")
		if strings.HasPrefix(header, prefix) && constantTimeEqual(strings.TrimPrefix(header, prefix), s.bearer) {
			return true
		}
	}
	if s.basicUser != "" || s.basicPass != "" {
		user, pass, ok := r.BasicAuth()
		if ok && constantTimeEqual(user, s.basicUser) && constantTimeEqual(pass, s.basicPass) {
			return true
		}
	}
	return false
}

func toRegistryRoute(route config.RouteConfig) registry.Route {
	return registry.Route{
		Name:             route.Name,
		Ecosystem:        route.Ecosystem,
		PathPrefix:       route.PathPrefix,
		UpstreamURL:      route.UpstreamURL,
		FileUpstreamURL:  route.FileUpstreamURL,
		UpstreamTokenEnv: route.UpstreamTokenEnv,
	}
}

func requestID(r *http.Request) string {
	if value := r.Header.Get("X-Request-ID"); value != "" {
		return value
	}
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func errorBody(code string, message string, requestID string) map[string]string {
	return map[string]string{"error": code, "message": message, "request_id": requestID}
}

func secretFromEnv(name string) (string, bool) {
	if name == "" {
		return "", true
	}
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		return "", false
	}
	return value, true
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func Run(ctx context.Context, cfg config.Config, policyEngine *policy.Engine, provider intel.Provider, runtimeConfigs ...RuntimeConfig) error {
	srv := New(cfg, policyEngine, provider, runtimeConfigs...).HTTPServer()
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Std())
		defer cancel()
		return errors.Join(srv.Shutdown(shutdownCtx), <-errCh)
	case err := <-errCh:
		return err
	}
}

type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens = min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
