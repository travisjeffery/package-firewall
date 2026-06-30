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

func TestIdentifyPyPIWheel(t *testing.T) {
	info := Identify(Route{Ecosystem: "pypi", PathPrefix: "/pypi/"}, "/pypi/files/packages/Django-5.0.6-py3-none-any.whl")
	if info.Package.PURL != "pkg:pypi/django@5.0.6" {
		t.Fatalf("purl = %q", info.Package.PURL)
	}
	if !info.FileUpstream {
		t.Fatal("expected file upstream")
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
}
