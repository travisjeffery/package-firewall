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

func DiscoverGradle(root, verificationPath string) (GradleManifest, error) {
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

	type artifactRecord struct {
		coordinate   string
		pluginMarker bool
		checksums    map[string]struct{}
	}
	artifactsByPath := make(map[string]*artifactRecord)
	foundComponents := make(map[string]struct{})
	pluginMarkers := make(map[string]struct{})
	for _, component := range components {
		coordinate := gradleCoordinate(component.Group, component.Name, component.Version)
		_, isLocked := locked[coordinate]
		isPluginMarker := strings.HasSuffix(component.Name, ".gradle.plugin")
		if !isLocked && !isPluginMarker {
			continue
		}
		if isLocked {
			foundComponents[coordinate] = struct{}{}
		}
		if isPluginMarker {
			pluginMarkers[coordinate] = struct{}{}
		}
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
			artifactPath, err := mavenArtifactPath(component, artifact.Name)
			if err != nil {
				return GradleManifest{}, fmt.Errorf("%s artifact %q: %w", coordinate, artifact.Name, err)
			}
			record := artifactsByPath[artifactPath]
			if record == nil {
				record = &artifactRecord{
					coordinate:   coordinate,
					pluginMarker: isPluginMarker,
					checksums:    make(map[string]struct{}),
				}
				artifactsByPath[artifactPath] = record
			} else if record.coordinate != coordinate {
				return GradleManifest{}, fmt.Errorf("artifact path %q belongs to multiple coordinates", artifactPath)
			}
			for _, checksum := range checksums {
				record.checksums[checksum] = struct{}{}
			}
		}
	}
	if len(artifactsByPath) == 0 {
		return GradleManifest{}, errors.New("no SHA-256-verified artifacts matched the locked Gradle components")
	}
	missing := missingCoordinates(locked, foundComponents)
	if len(missing) > 0 {
		return GradleManifest{}, fmt.Errorf("%d locked Gradle components are absent from verification metadata (first: %s)", len(missing), strings.Join(missing[:min(len(missing), 5)], ", "))
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
		PluginMarkers:     len(pluginMarkers),
		lockedCoordinates: locked,
	}, nil
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

func mavenArtifactPath(component verificationComponent, artifact string) (string, error) {
	groupParts := strings.Split(component.Group, ".")
	parts := make([]string, 0, len(groupParts)+3)
	parts = append(parts, groupParts...)
	parts = append(parts, component.Name, component.Version, artifact)
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
