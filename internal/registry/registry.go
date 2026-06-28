package registry

import (
	"net/url"
	"strings"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

type Route struct {
	Name             string
	Ecosystem        string
	PathPrefix       string
	UpstreamURL      string
	FileUpstreamURL  string
	UpstreamTokenEnv string
	CacheTTLSeconds  int64
}

type RequestInfo struct {
	Package       policy.Package
	Kind          string
	UpstreamPath  string
	FileUpstream  bool
	NeedsDecision bool
}

func Identify(route Route, requestPath string) RequestInfo {
	relative := strings.TrimPrefix(requestPath, route.PathPrefix)
	relative = strings.TrimPrefix(relative, "/")
	info := RequestInfo{Kind: "metadata", UpstreamPath: "/" + relative}
	switch route.Ecosystem {
	case "npm":
		return identifyNPM(route, relative, info)
	case "pypi":
		return identifyPyPI(route, relative, info)
	case "maven":
		return identifyMaven(route, relative, info)
	case "go":
		return identifyGo(route, relative, info)
	default:
		return info
	}
}

func purl(ecosystem, name, version string) string {
	if name == "" || version == "" {
		return ""
	}
	switch ecosystem {
	case "npm":
		return "pkg:npm/" + name + "@" + version
	case "pypi":
		return "pkg:pypi/" + name + "@" + version
	case "maven":
		return "pkg:maven/" + name + "@" + version
	case "go":
		return "pkg:golang/" + name + "@" + version
	default:
		return ""
	}
}

func unescapePathPart(value string) string {
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return value
	}
	return decoded
}

func trimKnownSuffix(value string, suffixes ...string) string {
	for _, suffix := range suffixes {
		value = strings.TrimSuffix(value, suffix)
	}
	return value
}
