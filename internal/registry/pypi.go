package registry

import (
	"regexp"
	"strings"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

var pypiNormalizeRE = regexp.MustCompile(`[-_.]+`)
var wheelRE = regexp.MustCompile(`^(.+?)-([0-9][^-]*)-.*\.whl$`)
var sdistRE = regexp.MustCompile(`^(.+?)-([0-9][A-Za-z0-9.!+_-]*)\.(?:tar\.gz|zip|tar\.bz2|tar\.xz)$`)

func identifyPyPI(route Route, relative string, info RequestInfo) RequestInfo {
	if strings.HasPrefix(relative, "files/") {
		info.FileUpstream = true
		info.Kind = "artifact"
		filename := lastPathPart(relative)
		name, version := parsePyPIFile(filename)
		info.NeedsDecision = true
		info.Package = policy.Package{
			Ecosystem: route.Ecosystem,
			Name:      normalizePyPI(name),
			Version:   version,
			PURL:      purl("pypi", normalizePyPI(name), version),
		}
		info.UpstreamPath = "/" + strings.TrimPrefix(relative, "files/")
		return info
	}
	if strings.HasPrefix(relative, "simple/") {
		parts := splitPath(relative)
		if len(parts) >= 2 {
			info.Package = policy.Package{Ecosystem: route.Ecosystem, Name: normalizePyPI(parts[1])}
		}
	}
	return info
}

func parsePyPIFile(filename string) (string, string) {
	if matches := wheelRE.FindStringSubmatch(filename); len(matches) == 3 {
		return matches[1], matches[2]
	}
	if matches := sdistRE.FindStringSubmatch(filename); len(matches) == 3 {
		return matches[1], matches[2]
	}
	return "", ""
}

func normalizePyPI(name string) string {
	return strings.ToLower(pypiNormalizeRE.ReplaceAllString(name, "-"))
}
