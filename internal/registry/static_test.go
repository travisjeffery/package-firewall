package registry

import "testing"

func staticRoute() Route {
	return Route{Name: "build-assets", Ecosystem: "static", PathPrefix: "/build-assets/"}
}

func TestIdentifyStaticIdentifiesAssetByFullPath(t *testing.T) {
	info := Identify(staticRoute(), "/build-assets/gradle/gradle-9.1.0-bin.zip")
	if info.Kind != "artifact" {
		t.Fatalf("kind = %q, want artifact", info.Kind)
	}
	if !info.Cacheable {
		t.Fatal("static assets must be cacheable")
	}
	if info.Package.Name != "gradle/gradle-9.1.0-bin.zip" {
		t.Fatalf("name = %q", info.Package.Name)
	}
	if info.Package.PURL != "pkg:generic/gradle/gradle-9.1.0-bin.zip@static" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if info.UpstreamPath != "/gradle/gradle-9.1.0-bin.zip" {
		t.Fatalf("upstream path = %q", info.UpstreamPath)
	}
}

// A static asset has no coordinate to look up, so the vulnerability query must
// be skipped rather than run and fail. Policy rules still apply.
func TestIdentifyStaticSkipsVulnerabilityCheckButKeepsPolicy(t *testing.T) {
	info := Identify(staticRoute(), "/build-assets/async-profiler/async-profiler-4.2-linux-x64.tar.gz")
	if !info.SkipVulnerabilityCheck {
		t.Fatal("static assets must skip the vulnerability query")
	}
	if !info.NeedsDecision {
		t.Fatal("static assets must still run policy evaluation")
	}
}

// Two different assets must never collide on one cache entry.
func TestIdentifyStaticDistinguishesPaths(t *testing.T) {
	a := Identify(staticRoute(), "/build-assets/gradle/gradle-9.1.0-bin.zip")
	b := Identify(staticRoute(), "/build-assets/gradle/gradle-8.5-bin.zip")
	if a.Package.PURL == b.Package.PURL {
		t.Fatalf("distinct assets share an identity: %q", a.Package.PURL)
	}
}

func TestIdentifyStaticRejectsNonArtifactPaths(t *testing.T) {
	for _, path := range []string{
		"/build-assets/",
		"/build-assets/gradle/",
		"/build-assets/../etc/passwd",
		"/build-assets/gradle/../../secret",
	} {
		info := Identify(staticRoute(), path)
		if info.Kind == "artifact" || info.Cacheable || info.NeedsDecision {
			t.Fatalf("%s was identified as a cacheable artifact", path)
		}
	}
}
