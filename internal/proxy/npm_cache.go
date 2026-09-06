package proxy

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/travisjeffery/package-firewall/internal/config"
)

func (p *Proxy) prepareNPMCacheResponse(resp *http.Response, route config.RouteConfig, target string, requestedAt, receivedAt time.Time) time.Time {
	if route.Ecosystem != "npm" || route.UpstreamTokenEnv != "" || p.shouldRewrite(route, resp) {
		return time.Time{}
	}
	upstream, err := url.Parse(target)
	if err != nil || upstream.User != nil || upstream.RawQuery != "" || upstream.ForceQuery {
		return time.Time{}
	}
	origin, err := config.NormalizeHTTPOrigin(upstream.Scheme + "://" + upstream.Host)
	if err != nil || origin != "https://registry.npmjs.org:443" {
		return time.Time{}
	}
	if resp.Request == nil || resp.Request.Header.Get("Authorization") != "" || resp.Request.Header.Get("Cookie") != "" {
		return time.Time{}
	}
	lifetime, ok := npmFreshnessLifetime(resp.Header)
	if !ok {
		return time.Time{}
	}
	for _, value := range resp.Header.Values("Set-Cookie") {
		if !validNPMCDNCookie(value) {
			return time.Time{}
		}
	}
	if len(resp.Header.Values("Age")) > 1 || len(resp.Header.Values("Date")) > 1 {
		return time.Time{}
	}
	var age time.Duration
	if values := resp.Header.Values("Age"); len(values) != 0 {
		var valid bool
		age, valid = npmDeltaSeconds(strings.TrimSpace(values[0]))
		if !valid {
			return time.Time{}
		}
	}
	age += max(receivedAt.Sub(requestedAt), 0)
	if values := resp.Header.Values("Date"); len(values) != 0 {
		date, err := http.ParseTime(values[0])
		if err != nil {
			return time.Time{}
		}
		age = max(age, receivedAt.Sub(date))
	}
	if age >= lifetime {
		return time.Time{}
	}
	// CDN visitor cookies must never be persisted or replayed to another client.
	candidate := *resp
	candidate.Header = resp.Header.Clone()
	candidate.Header.Del("Set-Cookie")
	if p.responseBypassReason(&candidate, target, true) != "" {
		return time.Time{}
	}
	candidate.Header.Set("Age", strconv.FormatInt(int64(age/time.Second), 10))
	resp.Header = candidate.Header
	return receivedAt.Add(lifetime - age)
}

func npmFreshnessLifetime(headers http.Header) (time.Duration, bool) {
	var public bool
	ages := make(map[string]time.Duration)
	for _, value := range headers.Values("Cache-Control") {
		if strings.ContainsAny(value, "\"\\") {
			return 0, false
		}
		for _, directive := range strings.Split(value, ",") {
			name, value, hasValue := strings.Cut(strings.TrimSpace(directive), "=")
			name = strings.ToLower(strings.TrimSpace(name))
			switch name {
			case "public", "immutable", "must-revalidate", "proxy-revalidate", "no-transform":
				if hasValue {
					return 0, false
				}
				public = public || name == "public"
			case "max-age", "s-maxage":
				if _, duplicate := ages[name]; duplicate || !hasValue {
					return 0, false
				}
				age, valid := npmDeltaSeconds(strings.TrimSpace(value))
				if !valid {
					return 0, false
				}
				ages[name] = age
			default:
				return 0, false
			}
		}
	}
	lifetime, ok := ages["s-maxage"]
	if !ok {
		lifetime = ages["max-age"]
	}
	return lifetime, public && lifetime > 0
}

func npmDeltaSeconds(value string) (time.Duration, bool) {
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return 0, false
	}
	seconds, err := strconv.ParseUint(value, 10, 32)
	return time.Duration(seconds) * time.Second, err == nil
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
