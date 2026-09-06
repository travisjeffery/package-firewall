package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/travisjeffery/package-firewall/internal/config"
)

func (p *Proxy) stripCacheableNPMCDNCookies(resp *http.Response, route config.RouteConfig, target string) {
	if route.Ecosystem != "npm" || route.UpstreamTokenEnv != "" || p.shouldRewrite(route, resp) {
		return
	}
	upstream, err := url.Parse(target)
	if err != nil || upstream.User != nil || upstream.RawQuery != "" || upstream.ForceQuery {
		return
	}
	origin, err := config.NormalizeHTTPOrigin(upstream.Scheme + "://" + upstream.Host)
	if err != nil || origin != "https://registry.npmjs.org:443" {
		return
	}
	if resp.Request == nil || resp.Request.Header.Get("Authorization") != "" || resp.Request.Header.Get("Cookie") != "" {
		return
	}
	var public, immutable bool
	for _, value := range resp.Header.Values("Cache-Control") {
		if strings.ContainsAny(value, "\"\\") {
			return
		}
		for _, directive := range strings.Split(value, ",") {
			switch strings.ToLower(strings.TrimSpace(directive)) {
			case "public":
				public = true
			case "immutable":
				immutable = true
			}
		}
	}
	if !public || !immutable {
		return
	}
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	for _, value := range cookies {
		if !validNPMCDNCookie(value) {
			return
		}
	}
	// CDN visitor cookies must never be persisted or replayed to another client.
	candidate := *resp
	candidate.Header = resp.Header.Clone()
	candidate.Header.Del("Set-Cookie")
	if p.responseBypassReason(&candidate, target) == "" {
		resp.Header = candidate.Header
	}
}

func validNPMCDNCookie(value string) bool {
	cookie, err := http.ParseSetCookie(value)
	if err != nil || len(cookie.Unparsed) != 0 || cookie.Valid() != nil || (cookie.Name != "__cf_bm" && cookie.Name != "_cfuvid") {
		return false
	}
	if strings.ContainsAny(cookie.Value, ", \t") {
		return false
	}
	for _, attribute := range strings.Split(value, ";")[1:] {
		name, value, hasValue := strings.Cut(strings.TrimSpace(attribute), "=")
		switch strings.ToLower(name) {
		case "secure", "httponly", "partitioned":
			if hasValue {
				return false
			}
		case "samesite":
			if !hasValue || (!strings.EqualFold(value, "none") && !strings.EqualFold(value, "lax") && !strings.EqualFold(value, "strict")) {
				return false
			}
		case "domain", "path", "max-age":
			if !hasValue || value == "" || strings.Contains(value, ",") {
				return false
			}
		case "expires":
			if !hasValue || cookie.Expires.IsZero() {
				return false
			}
		default:
			return false
		}
	}
	return true
}
