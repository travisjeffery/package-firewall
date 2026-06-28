package registry

import (
	"strings"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

func identifyGo(route Route, relative string, info RequestInfo) RequestInfo {
	const marker = "/@v/"
	idx := strings.Index(relative, marker)
	if idx < 0 {
		return info
	}
	module := unescapeGoModule(relative[:idx])
	file := relative[idx+len(marker):]
	version := file
	switch {
	case strings.HasSuffix(file, ".info"):
		version = strings.TrimSuffix(file, ".info")
	case strings.HasSuffix(file, ".mod"):
		version = strings.TrimSuffix(file, ".mod")
	case strings.HasSuffix(file, ".zip"):
		version = strings.TrimSuffix(file, ".zip")
	default:
		return info
	}
	info.Kind = "artifact"
	info.NeedsDecision = true
	info.Package = policy.Package{
		Ecosystem: route.Ecosystem,
		Name:      module,
		Version:   version,
		PURL:      purl("go", module, version),
	}
	return info
}

func unescapeGoModule(module string) string {
	// Go proxy paths encode uppercase letters as !x. Preserve other escaping so
	// the proxy path stays reversible without importing internal Go command code.
	var b strings.Builder
	for i := 0; i < len(module); i++ {
		if module[i] == '!' && i+1 < len(module) {
			next := module[i+1]
			if next >= 'a' && next <= 'z' {
				b.WriteByte(next - 32)
				i++
				continue
			}
		}
		b.WriteByte(module[i])
	}
	return b.String()
}
