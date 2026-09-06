package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/travisjeffery/package-firewall/internal/config"
)

func (p *Proxy) stripCacheableNPMCDNCookies(resp *http.Response, route config.RouteConfig, target string) {
	if route.Ecosystem != "npm" || route.UpstreamTokenEnv != "" {
		return
	}
	upstream, err := url.Parse(target)
	if err != nil || upstream.Scheme != "https" || upstream.Host != "registry.npmjs.org" || upstream.User != nil || upstream.RawQuery != "" || upstream.ForceQuery {
		return
	}
	if resp.Request == nil || resp.Request.Header.Get("Authorization") != "" || resp.Request.Header.Get("Cookie") != "" {
		return
	}
	var public, immutable bool
	for _, value := range resp.Header.Values("Cache-Control") {
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
		cookie, err := http.ParseSetCookie(value)
		if err != nil || len(cookie.Unparsed) != 0 || (cookie.Name != "__cf_bm" && cookie.Name != "_cfuvid") {
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
