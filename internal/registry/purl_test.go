package registry

import (
	"testing"

	"github.com/travisjeffery/package-firewall/internal/policy"
)

func TestPackageFromPURL(t *testing.T) {
	tests := []struct {
		purl string
		want policy.Package
	}{
		{"pkg:npm/shell-quote@1.9.0", policy.Package{Ecosystem: "npm", Name: "shell-quote", Version: "1.9.0", PURL: "pkg:npm/shell-quote@1.9.0"}},
		{"pkg:npm/%40babel/core@7.0.0", policy.Package{Ecosystem: "npm", Name: "@babel/core", Version: "7.0.0", PURL: "pkg:npm/@babel/core@7.0.0"}},
		{"pkg:npm/@babel/core@7.0.0", policy.Package{Ecosystem: "npm", Name: "@babel/core", Version: "7.0.0", PURL: "pkg:npm/@babel/core@7.0.0"}},
		{"pkg:pypi/Zope.Interface@5.0", policy.Package{Ecosystem: "pypi", Name: "zope-interface", Version: "5.0", PURL: "pkg:pypi/zope-interface@5.0"}},
		{"pkg:maven/io.kubernetes/client-java@21.0.2?type=jar", policy.Package{Ecosystem: "maven", Name: "io.kubernetes:client-java", Version: "21.0.2", PURL: "pkg:maven/io.kubernetes/client-java@21.0.2"}},
		{"pkg:npm/foo@1.2.3#lib/file.js", policy.Package{Ecosystem: "npm", Name: "foo", Version: "1.2.3", PURL: "pkg:npm/foo@1.2.3"}},
		{"pkg:npm/foo@1.2.3?arch=x64#lib/file.js", policy.Package{Ecosystem: "npm", Name: "foo", Version: "1.2.3", PURL: "pkg:npm/foo@1.2.3"}},
		{"pkg:golang/golang.org/x/mod@v0.30.0", policy.Package{Ecosystem: "go", Name: "golang.org/x/mod", Version: "v0.30.0", PURL: "pkg:golang/golang.org/x/mod@v0.30.0"}},
	}
	for _, tt := range tests {
		got, err := PackageFromPURL(tt.purl)
		if err != nil {
			t.Fatalf("%s: %v", tt.purl, err)
		}
		if got != tt.want {
			t.Fatalf("%s: got %+v, want %+v", tt.purl, got, tt.want)
		}
	}
	for _, bad := range []string{"npm/shell-quote@1.9.0", "pkg:npm/shell-quote", "pkg:npm/shell-quote@", "pkg:maven/client-java@1.0", "pkg:cargo/serde@1.0.0"} {
		if _, err := PackageFromPURL(bad); err == nil {
			t.Fatalf("%s: expected an error", bad)
		}
	}
}
