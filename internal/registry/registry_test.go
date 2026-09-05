package registry

import "testing"

func TestIdentifyNPMTarball(t *testing.T) {
	info := Identify(Route{Ecosystem: "npm", PathPrefix: "/npm/"}, "/npm/@scope/pkg/-/pkg-1.2.3.tgz")
	if info.Package.PURL != "pkg:npm/@scope/pkg@1.2.3" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if !info.NeedsDecision {
		t.Fatal("expected decision")
	}
}

func TestIdentifyNPMTarballWithPrereleaseAndBuildMetadata(t *testing.T) {
	info := Identify(Route{Ecosystem: "npm", PathPrefix: "/npm/"}, "/npm/pkg/-/pkg-1.2.3-beta.1+build.7.tgz")
	if info.Package.PURL != "pkg:npm/pkg@1.2.3-beta.1+build.7" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if !info.NeedsDecision {
		t.Fatal("expected decision")
	}
}

func TestIdentifyNPMUnparsedTarballRequiresDecision(t *testing.T) {
	info := Identify(Route{Ecosystem: "npm", PathPrefix: "/npm/"}, "/npm/pkg/-/pkg-not-a-semver.tgz")
	if info.Kind != "artifact" {
		t.Fatalf("kind = %q", info.Kind)
	}
	if info.Package.PURL != "" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if !info.NeedsDecision {
		t.Fatal("expected decision for unparsed artifact")
	}
}

func TestIdentifyPyPIWheel(t *testing.T) {
	info := Identify(Route{Ecosystem: "pypi", PathPrefix: "/pypi/"}, "/pypi/files/packages/Django-5.0.6-py3-none-any.whl")
	if info.Package.PURL != "pkg:pypi/django@5.0.6" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if !info.FileUpstream {
		t.Fatal("expected file upstream")
	}
}

func TestIdentifyPyPIUnparsedFileRequiresDecision(t *testing.T) {
	info := Identify(Route{Ecosystem: "pypi", PathPrefix: "/pypi/"}, "/pypi/files/packages/left_pad-not-a-version.whl")
	if info.Kind != "artifact" {
		t.Fatalf("kind = %q", info.Kind)
	}
	if !info.FileUpstream {
		t.Fatal("expected file upstream")
	}
	if info.Package.PURL != "" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if !info.NeedsDecision {
		t.Fatal("expected decision for unparsed artifact")
	}
}

func TestIdentifyMavenArtifact(t *testing.T) {
	info := Identify(Route{Ecosystem: "maven", PathPrefix: "/maven/"}, "/maven/org/apache/maven/apache-maven/3.8.4/apache-maven-3.8.4-bin.tar.gz")
	if info.Package.PURL != "pkg:maven/org.apache.maven/apache-maven@3.8.4" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
}

func TestIdentifyGoModule(t *testing.T) {
	info := Identify(Route{Ecosystem: "go", PathPrefix: "/go/"}, "/go/golang.org/x/mod/@v/v0.30.0.zip")
	if info.Package.PURL != "pkg:golang/golang.org/x/mod@v0.30.0" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if !info.NeedsDecision || info.SkipVulnerabilityCheck {
		t.Fatalf("decision fields = (%v, %v)", info.NeedsDecision, info.SkipVulnerabilityCheck)
	}
}

func TestIdentifyGoModuleMetadata(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		extension string
		cacheable bool
	}{
		{name: "canonical pseudo version info", version: "v0.0.0-20210220033148-5ea612d1eb83", extension: "info", cacheable: true},
		{name: "canonical release mod", version: "v0.30.0", extension: "mod", cacheable: true},
		{name: "canonical incompatible release info", version: "v2.0.0+incompatible", extension: "info", cacheable: true},
		{name: "branch info", version: "master", extension: "info", cacheable: false},
		{name: "version prefix mod", version: "v1.2", extension: "mod", cacheable: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := Identify(Route{Ecosystem: "go", PathPrefix: "/go/"}, "/go/golang.org/x/crypto/@v/"+test.version+"."+test.extension)
			if info.Package.PURL != "pkg:golang/golang.org/x/crypto@"+test.version {
				t.Fatalf("purl = %q", info.Package.PURL)
			}
			if info.Kind != "metadata" || !info.NeedsDecision || info.Cacheable != test.cacheable || !info.SkipVulnerabilityCheck {
				t.Fatalf("info = %#v", info)
			}
		})
	}
}
