package registry

import (
	"path"
	"regexp"
	"strings"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

var npmTarballVersionRE = regexp.MustCompile(`^(.+)-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\.tgz$`)

func identifyNPM(route Route, relative string, info RequestInfo) RequestInfo {
	parts := splitPath(relative)
	if len(parts) == 0 {
		return info
	}
	if len(parts) >= 3 && parts[len(parts)-2] == "-" && strings.HasSuffix(parts[len(parts)-1], ".tgz") {
		name := npmNameFromParts(parts[:len(parts)-2])
		version := npmVersionFromTarball(parts[len(parts)-1])
		info.Kind = "artifact"
		info.NeedsDecision = version != ""
		info.Package = policy.Package{
			Ecosystem: route.Ecosystem,
			Name:      name,
			Version:   version,
			PURL:      purl("npm", name, version),
		}
		return info
	}
	name := npmNameFromParts(parts)
	info.Package = policy.Package{Ecosystem: route.Ecosystem, Name: name}
	return info
}

func npmNameFromParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		return path.Join(unescapePathPart(parts[0]), unescapePathPart(parts[1]))
	}
	return unescapePathPart(parts[0])
}

func npmVersionFromTarball(filename string) string {
	matches := npmTarballVersionRE.FindStringSubmatch(filename)
	if len(matches) == 3 {
		return matches[2]
	}
	return ""
}
