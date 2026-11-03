package prewarm

import (
	"bufio"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Artifact struct {
	Coordinate   string
	Path         string
	SHA256       []string
	pluginMarker bool
}

type GradleManifest struct {
	Artifacts          []Artifact
	Lockfiles          int
	LockedComponents   int
	PluginMarkers      int
	ExcludedComponents int
	ExcludedArtifacts  int
	lockedCoordinates  map[string]struct{}
}

type verificationMetadata struct {
	Components []verificationComponent `xml:"components>component"`
}

type verificationComponent struct {
	Group     string                 `xml:"group,attr"`
	Name      string                 `xml:"name,attr"`
	Version   string                 `xml:"version,attr"`
	Artifacts []verificationArtifact `xml:"artifact"`
}

type verificationArtifact struct {
	Name    string                 `xml:"name,attr"`
	SHA256s []verificationChecksum `xml:"sha256"`
}

type verificationChecksum struct {
	Value string `xml:"value,attr"`
}

func DiscoverGradle(root, verificationPath string, activePluginMarkerValues ...string) (GradleManifest, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return GradleManifest{}, fmt.Errorf("resolve Gradle root: %w", err)
	}
	locked, lockfiles, err := readGradleLocks(root)
	if err != nil {
		return GradleManifest{}, err
	}
	if lockfiles == 0 {
		return GradleManifest{}, fmt.Errorf("no gradle.lockfile files found under %s", root)
	}
	if len(locked) == 0 {
		return GradleManifest{}, errors.New("Gradle lockfiles contain no external component coordinates")
	}
	if verificationPath == "" {
		verificationPath = filepath.Join(root, "gradle", "verification-metadata.xml")
	} else if !filepath.IsAbs(verificationPath) {
		verificationPath = filepath.Join(root, verificationPath)
	}
	components, err := readVerificationMetadata(verificationPath)
	if err != nil {
		return GradleManifest{}, err
	}
	activePluginMarkers, err := validatePluginMarkerCoordinates(activePluginMarkerValues)
	if err != nil {
		return GradleManifest{}, err
	}

	type artifactRecord struct {
		coordinate   string
		pluginMarker bool
		checksums    map[string]struct{}
	}
	artifactsByPath := make(map[string]*artifactRecord)
	foundComponents := make(map[string]struct{})
	foundPluginMarkers := make(map[string]struct{})
	versionsByModule := make(map[string][]string)
	for _, component := range components {
		module := component.Group + ":" + component.Name
		versionsByModule[module] = append(versionsByModule[module], component.Version)
	}
	for _, component := range components {
		coordinate := gradleCoordinate(component.Group, component.Name, component.Version)
		_, isLocked := locked[coordinate]
		_, isActivePluginMarker := activePluginMarkers[coordinate]
		if !isLocked && !isActivePluginMarker {
			continue
		}
		if isLocked {
			foundComponents[coordinate] = struct{}{}
		}
		foundArtifact := false
		for _, artifact := range component.Artifacts {
			if ignoredGradleArtifact(artifact.Name) {
				continue
			}
			checksums, err := validSHA256s(artifact.SHA256s)
			if err != nil {
				return GradleManifest{}, fmt.Errorf("%s artifact %q: %w", coordinate, artifact.Name, err)
			}
			if len(checksums) == 0 {
				continue
			}
			foundArtifact = true
			module := component.Group + ":" + component.Name
			publishedVersion := publishedArtifactVersion(component, artifact.Name, versionsByModule[module])
			artifactPath, err := mavenArtifactPath(component, publishedVersion, artifact.Name)
			if err != nil {
				return GradleManifest{}, fmt.Errorf("%s artifact %q: %w", coordinate, artifact.Name, err)
			}
			publishedCoordinate := gradleCoordinate(component.Group, component.Name, publishedVersion)
			record := artifactsByPath[artifactPath]
			if record == nil {
				record = &artifactRecord{
					coordinate:   publishedCoordinate,
					pluginMarker: isActivePluginMarker,
					checksums:    make(map[string]struct{}),
				}
				artifactsByPath[artifactPath] = record
			} else if record.coordinate != publishedCoordinate {
				return GradleManifest{}, fmt.Errorf("artifact path %q belongs to multiple coordinates", artifactPath)
			}
			for _, checksum := range checksums {
				record.checksums[checksum] = struct{}{}
			}
		}
		if isActivePluginMarker && foundArtifact {
			foundPluginMarkers[coordinate] = struct{}{}
		}
	}
	if len(artifactsByPath) == 0 {
		return GradleManifest{}, errors.New("no SHA-256-verified artifacts matched the locked Gradle components")
	}
	missing := missingCoordinates(locked, foundComponents)
	if len(missing) > 0 {
		return GradleManifest{}, fmt.Errorf("%d locked Gradle components are absent from verification metadata (first: %s)", len(missing), strings.Join(missing[:min(len(missing), 5)], ", "))
	}
	missingPluginMarkers := missingCoordinates(activePluginMarkers, foundPluginMarkers)
	if len(missingPluginMarkers) > 0 {
		return GradleManifest{}, fmt.Errorf("%d active Gradle plugin markers have no SHA-256-verified artifact in verification metadata (first: %s)", len(missingPluginMarkers), strings.Join(missingPluginMarkers[:min(len(missingPluginMarkers), 5)], ", "))
	}

	paths := make([]string, 0, len(artifactsByPath))
	for artifactPath := range artifactsByPath {
		paths = append(paths, artifactPath)
	}
	sort.Strings(paths)
	artifacts := make([]Artifact, 0, len(paths))
	for _, artifactPath := range paths {
		record := artifactsByPath[artifactPath]
		checksums := make([]string, 0, len(record.checksums))
		for checksum := range record.checksums {
			checksums = append(checksums, checksum)
		}
		sort.Strings(checksums)
		artifacts = append(artifacts, Artifact{
			Coordinate:   record.coordinate,
			Path:         artifactPath,
			SHA256:       checksums,
			pluginMarker: record.pluginMarker,
		})
	}
	return GradleManifest{
		Artifacts:         artifacts,
		Lockfiles:         lockfiles,
		LockedComponents:  len(locked),
		PluginMarkers:     len(foundPluginMarkers),
		lockedCoordinates: locked,
	}, nil
}

func validatePluginMarkerCoordinates(values []string) (map[string]struct{}, error) {
	markers := make(map[string]struct{})
	for _, value := range values {
		coordinate := strings.TrimSpace(value)
		parts := strings.Split(coordinate, ":")
		if len(parts) != 3 || !safeMavenSegment(parts[0]) || !safeMavenSegment(parts[1]) || !safeMavenSegment(parts[2]) || parts[1] != parts[0]+".gradle.plugin" {
			return nil, fmt.Errorf("invalid active Gradle plugin marker coordinate %q", value)
		}
		markers[coordinate] = struct{}{}
	}
	return markers, nil
}

func ExcludeGradleCoordinates(manifest GradleManifest, values []string) (GradleManifest, error) {
	excluded := make(map[string]struct{})
	for _, value := range values {
		coordinate := strings.TrimSpace(value)
		if coordinate == "" {
			return GradleManifest{}, errors.New("excluded Gradle coordinate must not be empty")
		}
		parts := strings.Split(coordinate, ":")
		if len(parts) != 3 || !safeMavenSegment(parts[0]) || !safeMavenSegment(parts[1]) || !safeMavenSegment(parts[2]) {
			return GradleManifest{}, fmt.Errorf("invalid excluded Gradle coordinate %q", value)
		}
		if _, ok := manifest.lockedCoordinates[coordinate]; !ok {
			return GradleManifest{}, fmt.Errorf("excluded Gradle coordinate %q is not locked", coordinate)
		}
		excluded[coordinate] = struct{}{}
	}
	if len(excluded) == 0 {
		return manifest, nil
	}

	artifacts := make([]Artifact, 0, len(manifest.Artifacts))
	excludedArtifacts := 0
	for _, artifact := range manifest.Artifacts {
		if _, ok := excluded[artifact.Coordinate]; ok {
			excludedArtifacts++
			continue
		}
		artifacts = append(artifacts, artifact)
	}
	if len(artifacts) == 0 {
		return GradleManifest{}, errors.New("excluded Gradle coordinates remove every prewarm artifact")
	}
	manifest.Artifacts = artifacts
	manifest.ExcludedComponents = len(excluded)
	manifest.ExcludedArtifacts = excludedArtifacts
	return manifest, nil
}

func readGradleLocks(root string) (map[string]struct{}, int, error) {
	locked := make(map[string]struct{})
	lockfiles := 0
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && ignoredDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "gradle.lockfile" {
			return nil
		}
		coordinates, err := readGradleLock(path)
		if err != nil {
			return err
		}
		lockfiles++
		for coordinate := range coordinates {
			locked[coordinate] = struct{}{}
		}
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("discover Gradle lockfiles: %w", err)
	}
	return locked, lockfiles, nil
}

func readGradleLock(path string) (map[string]struct{}, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	coordinates := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		coordinate, _, ok := strings.Cut(line, "=")
		coordinate = strings.TrimSpace(coordinate)
		if !ok {
			return nil, fmt.Errorf("%s:%d: lock entry is missing '='", path, lineNumber)
		}
		if coordinate == "empty" {
			continue
		}
		parts := strings.Split(coordinate, ":")
		if len(parts) != 3 || !safeMavenSegment(parts[0]) || !safeMavenSegment(parts[1]) || !safeMavenSegment(parts[2]) {
			return nil, fmt.Errorf("%s:%d: invalid locked component %q", path, lineNumber, coordinate)
		}
		coordinates[coordinate] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return coordinates, nil
}

func readVerificationMetadata(path string) ([]verificationComponent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Gradle verification metadata %s: %w", path, err)
	}
	defer file.Close()
	var metadata verificationMetadata
	decoder := xml.NewDecoder(file)
	if err := decoder.Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode Gradle verification metadata %s: %w", path, err)
	}
	return metadata.Components, nil
}

func validSHA256s(values []verificationChecksum) ([]string, error) {
	checksums := make([]string, 0, len(values))
	for _, value := range values {
		checksum := strings.ToLower(strings.TrimSpace(value.Value))
		raw, err := hex.DecodeString(checksum)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("invalid SHA-256 %q", value.Value)
		}
		checksums = append(checksums, checksum)
	}
	return checksums, nil
}

// publishedArtifactVersion reports the version directory an artifact is actually
// published under. Gradle Module Metadata lets one component's variant point at a
// file published beside a different version: com.google.guava:guava:33.4.8-android
// declares its JRE variant as ../33.4.8-jre/guava-33.4.8-jre.jar, and Gradle records
// that file under the -android component. Fetching it from the component's own
// version directory 404s, so trust the file name when it names a sibling version.
func publishedArtifactVersion(component verificationComponent, artifact string, moduleVersions []string) string {
	published := ""
	for _, version := range append([]string{component.Version}, moduleVersions...) {
		if !namesVersion(artifact, component.Name, version) {
			continue
		}
		// Longest wins: 1.2 also prefixes library-1.2.1.jar, which belongs to 1.2.1.
		if len(version) > len(published) {
			published = version
		}
	}
	if published == "" {
		return component.Version
	}
	return published
}

// namesVersion reports whether a Maven file name is <name>-<version> followed by
// an extension or a classifier, rather than merely sharing a version prefix.
func namesVersion(artifact, name, version string) bool {
	prefix := name + "-" + version
	if !strings.HasPrefix(artifact, prefix) {
		return false
	}
	boundary := artifact[len(prefix):]
	return strings.HasPrefix(boundary, ".") || strings.HasPrefix(boundary, "-")
}

func mavenArtifactPath(component verificationComponent, version, artifact string) (string, error) {
	groupParts := strings.Split(component.Group, ".")
	parts := make([]string, 0, len(groupParts)+3)
	parts = append(parts, groupParts...)
	parts = append(parts, component.Name, version, artifact)
	for _, part := range parts {
		if !safeMavenSegment(part) {
			return "", fmt.Errorf("unsafe Maven path segment %q", part)
		}
	}
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	return strings.Join(parts, "/"), nil
}

func gradleCoordinate(group, name, version string) string {
	return group + ":" + name + ":" + version
}

func missingCoordinates(locked, found map[string]struct{}) []string {
	missing := make([]string, 0)
	for coordinate := range locked {
		if _, ok := found[coordinate]; !ok {
			missing = append(missing, coordinate)
		}
	}
	sort.Strings(missing)
	return missing
}

func ignoredDirectory(name string) bool {
	switch name {
	case ".git", ".gradle", "build", "node_modules", "out":
		return true
	default:
		return false
	}
}

func ignoredGradleArtifact(name string) bool {
	return strings.HasSuffix(name, "-sources.jar") || strings.HasSuffix(name, "-javadoc.jar")
}

func safeMavenSegment(value string) bool {
	return value != "" && value != "." && value != ".." && !strings.ContainsAny(value, `/\\`)
}
