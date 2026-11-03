package registry

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/travisjeffery/tidewaiter/internal/policy"
)

type Route struct {
	Name             string
	Ecosystem        string
	PathPrefix       string
	UpstreamURL      string
	FileUpstreamURL  string
	UpstreamTokenEnv string
}

type RequestInfo struct {
	Package                policy.Package
	Kind                   string
	UpstreamPath           string
	FileUpstream           bool
	NeedsDecision          bool
	Cacheable              bool
	SkipVulnerabilityCheck bool
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
	case "static":
		return identifyStatic(route, relative, info)
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

// PackageFromPURL parses the purl forms this firewall logs and matches policy
// against, e.g. pkg:npm/@scope/name@1.0.0 or pkg:maven/group/artifact@1.0.
func PackageFromPURL(raw string) (policy.Package, error) {
	rest, ok := strings.CutPrefix(raw, "pkg:")
	if !ok {
		return policy.Package{}, fmt.Errorf("purl %q must start with pkg:", raw)
	}
	purlType, rest, ok := strings.Cut(rest, "/")
	if !ok {
		return policy.Package{}, fmt.Errorf("purl %q has no name", raw)
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	at := strings.LastIndex(rest, "@")
	if at <= 0 || at == len(rest)-1 {
		return policy.Package{}, fmt.Errorf("purl %q needs a name and an exact version", raw)
	}
	name := unescapePathPart(rest[:at])
	version := unescapePathPart(rest[at+1:])
	var ecosystem, policyName string
	switch purlType {
	case "npm":
		ecosystem, policyName = "npm", name
	case "pypi":
		ecosystem, policyName = "pypi", normalizePyPI(name)
		name = policyName
	case "maven":
		group, artifact, ok := strings.Cut(name, "/")
		if !ok {
			return policy.Package{}, fmt.Errorf("maven purl %q needs group/artifact", raw)
		}
		ecosystem, policyName = "maven", group+":"+artifact
	case "golang":
		ecosystem, policyName = "go", name
	default:
		return policy.Package{}, fmt.Errorf("unsupported purl type %q", purlType)
	}
	return policy.Package{
		Ecosystem: ecosystem,
		Name:      policyName,
		Version:   version,
		PURL:      purl(ecosystem, name, version),
	}, nil
}
