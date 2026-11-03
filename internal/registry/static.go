package registry

import (
	"strings"

	"github.com/travisjeffery/tidewaiter/internal/policy"
)

// identifyStatic handles routes that mirror fixed build assets -- a Gradle
// distribution zip, a profiler tarball -- rather than a package registry.
//
// These have no package coordinate, so no OSV query is possible and none is
// attempted: SkipVulnerabilityCheck short-circuits decide() after the policy
// rules run. Integrity is not weakened by that, because every consumer of this
// route pins the artifact by checksum (Gradle's distributionSha256Sum, a
// `sha256sum -c` in a Dockerfile); the firewall's job here is to keep the fetch
// on an internal, authenticated path, not to judge the contents.
//
// The synthetic identity is what makes the response cacheable -- cacheKey
// requires a fully identified artifact so one path can never be served from
// another's entry -- and it still lets an explicit policy deny rule pin an
// individual asset by name.
func identifyStatic(route Route, relative string, info RequestInfo) RequestInfo {
	if relative == "" || strings.HasSuffix(relative, "/") {
		return info
	}
	parts := splitPath(relative)
	if len(parts) == 0 {
		return info
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return info
		}
	}
	name := strings.Join(parts, "/")
	info.Kind = "artifact"
	info.Cacheable = true
	info.NeedsDecision = true
	info.SkipVulnerabilityCheck = true
	info.Package = policy.Package{
		Ecosystem: route.Ecosystem,
		Name:      name,
		Version:   staticAssetVersion,
		PURL:      "pkg:generic/" + name + "@" + staticAssetVersion,
	}
	return info
}

// staticAssetVersion is a constant because a mirrored asset's identity is its
// full path; the version component exists only to satisfy the exact-artifact
// requirements that gate caching.
const staticAssetVersion = "static"
