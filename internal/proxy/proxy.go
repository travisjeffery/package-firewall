package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
	"github.com/travisjeffery/package-firewall/internal/registry"
)

const defaultUpstreamTimeout = 30 * time.Second

type Proxy struct {
	client  *http.Client
	baseURL string
}

func New(baseURL string) *Proxy {
	return &Proxy{
		client:  &http.Client{Timeout: defaultUpstreamTimeout},
		baseURL: strings.TrimRight(baseURL, "/"),
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
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
	if err != nil {
		return Result{}, err
	}
	copyRequestHeaders(req.Header, r.Header)
	if route.UpstreamTokenEnv != "" {
		if token := os.Getenv(route.UpstreamTokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	copyResponseHeaders(w.Header(), resp.Header)
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
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return Result{StatusCode: resp.StatusCode}, err
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
	copyHeaders(dst, src, func(string) bool { return false })
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
		"x-amzn-oidc-data",
		"x-amzn-oidc-accesstoken",
		"x-auth-request-access-token",
		"x-auth-request-email",
		"x-forwarded-access-token":
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
