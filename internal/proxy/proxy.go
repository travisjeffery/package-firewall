package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/objectcache"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

type Proxy struct {
	client  *http.Client
	baseURL string
	cache   CacheConfig
}

type CacheConfig struct {
	Store                objectcache.Store
	ArtifactTTL          time.Duration
	ArtifactStaleIfError time.Duration
	MaxObjectSize        int64
}

func New(baseURL string, cacheConfig ...CacheConfig) *Proxy {
	var cache CacheConfig
	if len(cacheConfig) > 0 {
		cache = cacheConfig[0]
	}
	return &Proxy{
		client:  &http.Client{Timeout: 0},
		baseURL: strings.TrimRight(baseURL, "/"),
		cache:   cache,
	}
}

type Result struct {
	StatusCode int
}

func (p *Proxy) Serve(w http.ResponseWriter, r *http.Request, route config.RouteConfig, info registry.RequestInfo) (Result, error) {
	target, err := upstreamURL(route, info)
	if err != nil {
		return Result{}, err
	}
	cacheKey, cacheable := p.cacheKey(r.Method, route, info, target)
	var stale objectcache.Entry
	var hasStale bool
	if cacheable {
		cached, ok, err := p.cache.Store.Get(r.Context(), cacheKey)
		if err == nil && ok {
			if cached.Fresh(time.Now()) {
				return p.serveCached(w, cached, "HIT")
			}
			stale = cached
			hasStale = true
		}
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		return Result{}, err
	}
	copyHeaders(req.Header, r.Header)
	req.Header.Del("Authorization")
	req.Header.Del("Proxy-Authorization")
	if route.UpstreamTokenEnv != "" {
		if token := os.Getenv(route.UpstreamTokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		if hasStale && stale.CanServeOnError(time.Now()) {
			return p.serveCached(w, stale, "STALE")
		}
		return Result{}, err
	}
	if hasStale {
		_ = stale.Body.Close()
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	rewrite := p.shouldRewrite(route, resp)
	if rewrite {
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
	if cacheable && p.canStore(resp) {
		return p.serveAndStore(w, r, resp, cacheKey)
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return Result{StatusCode: resp.StatusCode}, err
}

func (p *Proxy) cacheKey(method string, route config.RouteConfig, info registry.RequestInfo, target string) (string, bool) {
	if p.cache.Store == nil || method != http.MethodGet || info.Kind != "artifact" || !info.NeedsDecision {
		return "", false
	}
	return objectcache.Key(method, route.Name, route.Ecosystem, target), true
}

func (p *Proxy) canStore(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return false
	}
	if p.cache.MaxObjectSize > 0 && resp.ContentLength > p.cache.MaxObjectSize {
		return false
	}
	return true
}

func (p *Proxy) serveCached(w http.ResponseWriter, cached objectcache.Entry, cacheStatus string) (Result, error) {
	defer cached.Body.Close()
	copyHeaders(w.Header(), cached.Headers)
	w.Header().Set("X-Package-Firewall-Cache", cacheStatus)
	w.WriteHeader(cached.StatusCode)
	_, err := io.Copy(w, cached.Body)
	return Result{StatusCode: cached.StatusCode}, err
}

func (p *Proxy) serveAndStore(w http.ResponseWriter, r *http.Request, resp *http.Response, cacheKey string) (Result, error) {
	tmp, err := os.CreateTemp("", "package-firewall-cache-*")
	if err != nil {
		w.WriteHeader(resp.StatusCode)
		_, copyErr := io.Copy(w, resp.Body)
		return Result{StatusCode: resp.StatusCode}, copyErr
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	hasher := sha256.New()
	w.WriteHeader(resp.StatusCode)
	written, copyErr := io.Copy(io.MultiWriter(w, tmp, hasher), resp.Body)
	if copyErr != nil {
		return Result{StatusCode: resp.StatusCode}, copyErr
	}
	if p.cache.MaxObjectSize > 0 && written > p.cache.MaxObjectSize {
		return Result{StatusCode: resp.StatusCode}, nil
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return Result{StatusCode: resp.StatusCode}, nil
	}
	putErr := p.cache.Store.Put(r.Context(), objectcache.PutRequest{
		Key:            cacheKey,
		StatusCode:     resp.StatusCode,
		Headers:        resp.Header,
		Body:           tmp,
		TTL:            p.cache.ArtifactTTL,
		StaleIfError:   p.cache.ArtifactStaleIfError,
		Immutable:      true,
		ContentLength:  written,
		ComputedSHA256: hex.EncodeToString(hasher.Sum(nil)),
	})
	if putErr != nil {
		return Result{StatusCode: resp.StatusCode}, nil
	}
	return Result{StatusCode: resp.StatusCode}, nil
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
	path := "/" + strings.TrimLeft(info.UpstreamPath, "/")
	base.Path = prefix + path
	return base.String(), nil
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

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if hopByHop(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
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
