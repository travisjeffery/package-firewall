package registry

import (
	"strings"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

func identifyMaven(route Route, relative string, info RequestInfo) RequestInfo {
	parts := splitPath(relative)
	if len(parts) < 4 {
		return info
	}
	filename := parts[len(parts)-1]
	version := parts[len(parts)-2]
	artifactID := parts[len(parts)-3]
	if strings.HasPrefix(filename, "maven-metadata.xml") || strings.HasSuffix(filename, ".sha1") || strings.HasSuffix(filename, ".md5") || strings.HasSuffix(filename, ".sha256") || strings.HasSuffix(filename, ".sha512") {
		return info
	}
	if !strings.HasPrefix(filename, artifactID+"-"+version) {
		return info
	}
	groupID := strings.Join(parts[:len(parts)-3], ".")
	name := groupID + "/" + artifactID
	info.Kind = "artifact"
	info.NeedsDecision = true
	info.Package = policy.Package{
		Ecosystem: route.Ecosystem,
		Name:      groupID + ":" + artifactID,
		Version:   version,
		PURL:      purl("maven", name, version),
	}
	return info
}
