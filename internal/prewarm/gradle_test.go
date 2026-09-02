package prewarm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverGradleBuildsVerifiedMavenArtifactManifest(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "service", "gradle.lockfile"), `
# generated
org.example:library:1.2.3=compileClasspath,runtimeClasspath
org.example:metadata-only:2.0=compileClasspath
empty=testRuntimeClasspath
`)
	writeFile(t, filepath.Join(root, "gradle", "verification-metadata.xml"), `
<verification-metadata>
  <components>
    <component group="org.example" name="library" version="1.2.3">
      <artifact name="library-1.2.3.jar"><sha256 value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"/></artifact>
      <artifact name="library-1.2.3.pom"><sha256 value="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"/></artifact>
      <artifact name="library-1.2.3-sources.jar"><sha256 value="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"/></artifact>
    </component>
    <component group="org.example" name="metadata-only" version="2.0">
      <artifact name="metadata-only-2.0.module"><sha256 value="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"/></artifact>
    </component>
    <component group="org.example" name="unlocked" version="9.0">
      <artifact name="unlocked-9.0.jar"><sha256 value="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"/></artifact>
    </component>
  </components>
</verification-metadata>
`)

	manifest, err := DiscoverGradle(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Lockfiles != 1 || manifest.LockedComponents != 2 {
		t.Fatalf("manifest counts = %#v", manifest)
	}
	want := []Artifact{
		{Path: "org/example/library/1.2.3/library-1.2.3.jar", SHA256: []string{strings.Repeat("a", 64)}},
		{Path: "org/example/library/1.2.3/library-1.2.3.pom", SHA256: []string{strings.Repeat("b", 64)}},
		{Path: "org/example/metadata-only/2.0/metadata-only-2.0.module", SHA256: []string{strings.Repeat("d", 64)}},
	}
	if len(manifest.Artifacts) != len(want) {
		t.Fatalf("artifacts = %#v", manifest.Artifacts)
	}
	for index := range want {
		if manifest.Artifacts[index].Path != want[index].Path || strings.Join(manifest.Artifacts[index].SHA256, ",") != strings.Join(want[index].SHA256, ",") {
			t.Fatalf("artifact %d = %#v want %#v", index, manifest.Artifacts[index], want[index])
		}
	}
}

func TestDiscoverGradleRequiresVerificationCoverage(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "gradle.lockfile"), "org.example:missing:1.0=runtimeClasspath\n")
	writeFile(t, filepath.Join(root, "gradle", "verification-metadata.xml"), "<verification-metadata><components/></verification-metadata>")
	_, err := DiscoverGradle(root, "")
	if err == nil || !strings.Contains(err.Error(), "no SHA-256-verified artifacts") {
		t.Fatalf("error = %v", err)
	}
}

func TestDiscoverGradleRejectsMalformedLockEntry(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "gradle.lockfile"), "not-a-coordinate=runtimeClasspath\n")
	writeFile(t, filepath.Join(root, "gradle", "verification-metadata.xml"), "<verification-metadata><components/></verification-metadata>")
	_, err := DiscoverGradle(root, "")
	if err == nil || !strings.Contains(err.Error(), "invalid locked component") {
		t.Fatalf("error = %v", err)
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
