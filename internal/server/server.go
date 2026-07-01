package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/travisjeffery/package-firewall/internal/audit"
	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/intel"
	"github.com/travisjeffery/package-firewall/internal/policy"
	"github.com/travisjeffery/package-firewall/internal/proxy"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

type Server struct {
	cfg       config.Config
	policy    *policy.Engine
	intel     intel.Provider
	proxy     *proxy.Proxy
	audit     *audit.Logger
	logger    *slog.Logger
	routes    []config.RouteConfig
	bearer    string
	basicUser string
	basicPass string
	authReady bool
}

func New(cfg config.Config, policyEngine *policy.Engine, provider intel.Provider, cacheConfig ...proxy.CacheConfig) *Server {
	routes := append([]config.RouteConfig(nil), cfg.Routes...)
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].PathPrefix) > len(routes[j].PathPrefix)
	})
	if provider == nil {
		provider = intel.NoopProvider{}
	}
	bearer, bearerOK := secretFromEnv(cfg.Auth.BearerTokenEnv)
	basicUser, basicUserOK := secretFromEnv(cfg.Auth.BasicUsernameEnv)
	basicPass, basicPassOK := secretFromEnv(cfg.Auth.BasicPasswordEnv)
	return &Server{
		cfg:       cfg,
		policy:    policyEngine,
		intel:     provider,
		proxy:     proxy.New(cfg.Server.PublicBaseURL, cacheConfig...),
		audit:     audit.New(),
		logger:    slog.New(slog.NewJSONHandler(os.Stdout, nil)),
		routes:    routes,
		bearer:    bearer,
		basicUser: basicUser,
		basicPass: basicPass,
		authReady: bearerOK && basicUserOK && basicPassOK,
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
	mux.HandleFunc("/", s.handle)
	return mux
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	w.Header().Set("X-Request-ID", requestID)
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="package-firewall"`)
		writeJSON(w, http.StatusUnauthorized, errorBody("unauthorized", "missing or invalid package firewall credentials", requestID))
		return
	}
	route, ok := s.matchRoute(r.URL.Path)
	if !ok {
		var fallback bool
		route, fallback = s.matchNPMTarballFallback(r.URL.Path)
		if !fallback {
			writeJSON(w, http.StatusNotFound, errorBody("not_found", "no package firewall route matched this path", requestID))
			return
		}
	}
	info := registry.Identify(toRegistryRoute(route), r.URL.Path)
	decision := s.decide(r.Context(), info)
	event := audit.FromDecision(r, route.Name, info.Package, requestID, decision)
	if decision.Action == policy.ActionBlock {
		s.audit.Log(event)
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "blocked",
			"request_id": requestID,
			"purl":       info.Package.PURL,
			"reason":     decision.Reason,
			"rule":       decision.MatchedRule,
		})
		return
	}
	result, err := s.proxy.Serve(w, r, route, info)
	event.UpstreamStatus = result.StatusCode
	if err != nil {
		event.Error = err.Error()
		s.audit.Log(event)
		s.logger.Error("proxy_failed", "request_id", requestID, "error", err)
		return
	}
	s.audit.Log(event)
}

func (s *Server) decide(ctx context.Context, info registry.RequestInfo) policy.Decision {
	if !info.NeedsDecision {
		return policy.Decision{Action: policy.ActionAllow, Reason: "metadata request"}
	}
	policyDecision := s.policy.Evaluate(info.Package)
	switch policyDecision.Action {
	case policy.ActionBlock, policy.ActionWarn, policy.ActionMonitor:
		return policyDecision
	case policy.ActionAllow:
		if policyDecision.MatchedRule != "" {
			return policyDecision
		}
	case policy.ActionUnknown:
		if s.cfg.Decision.FailOpenUnknownPackage {
			return policy.Decision{Action: policy.ActionWarn, Reason: "unknown package allowed by fail_open_unknown_package"}
		}
		return policy.Decision{Action: policy.ActionBlock, Reason: "unknown package blocked by fail_open_unknown_package=false"}
	}
	result, err := s.intel.Query(ctx, info.Package)
	if err != nil {
		if s.cfg.Decision.FailOpenIntelErrors {
			return policy.Decision{Action: policy.ActionWarn, Reason: "intel error allowed by fail_open_intel_errors: " + err.Error()}
		}
		return policy.Decision{Action: policy.ActionBlock, Reason: "intel error blocked by fail_open_intel_errors=false: " + err.Error()}
	}
	intelDecision := intel.Decide(result, policy.Action(s.cfg.Decision.DefaultVulnerabilityAction), s.cfg.Decision.VulnerabilityBlockThreshold)
	if intelDecision.Action == policy.ActionAllow {
		return policy.Decision{Action: policy.ActionAllow, Reason: "policy and intel allowed package"}
	}
	return intelDecision
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
		CacheTTLSeconds:  int64(route.CacheTTL.Std() / time.Second),
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

func Run(ctx context.Context, cfg config.Config, policyEngine *policy.Engine, provider intel.Provider, cacheConfig ...proxy.CacheConfig) error {
	srv := New(cfg, policyEngine, provider, cacheConfig...).HTTPServer()
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
