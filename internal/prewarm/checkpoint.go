package prewarm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const checkpointVersion = 1

type checkpoint struct {
	mu             sync.Mutex
	path           string
	manifestSHA256 string
	entries        map[string]checkpointEntry
}

type checkpointFile struct {
	Version        int                        `json:"version"`
	ManifestSHA256 string                     `json:"manifest_sha256"`
	Completed      map[string]checkpointEntry `json:"completed"`
}

type checkpointEntry struct {
	Route  string `json:"route"`
	Status string `json:"status"`
}

type manifestFingerprint struct {
	BaseURL           string                `json:"base_url"`
	RoutePrefix       string                `json:"route_prefix"`
	PluginRoutePrefix string                `json:"plugin_route_prefix"`
	Artifacts         []artifactFingerprint `json:"artifacts"`
}

type artifactFingerprint struct {
	Coordinate   string   `json:"coordinate"`
	Path         string   `json:"path"`
	SHA256       []string `json:"sha256"`
	PluginMarker bool     `json:"plugin_marker"`
}

func loadCheckpoint(path string, cfg RunConfig, artifacts []Artifact) (*checkpoint, error) {
	if path == "" {
		return nil, nil
	}
	manifestSHA256, err := fingerprintManifest(cfg, artifacts)
	if err != nil {
		return nil, err
	}
	state := &checkpoint{
		path:           path,
		manifestSHA256: manifestSHA256,
		entries:        make(map[string]checkpointEntry),
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read prewarm checkpoint: %w", err)
	}
	var file checkpointFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode prewarm checkpoint: %w", err)
	}
	if file.Version != checkpointVersion {
		return nil, fmt.Errorf("prewarm checkpoint version %d is unsupported", file.Version)
	}
	if file.ManifestSHA256 != manifestSHA256 {
		return nil, errors.New("prewarm checkpoint does not match the current manifest or route configuration")
	}
	validRoutes := make(map[string]string, len(artifacts))
	for _, artifact := range artifacts {
		route := cfg.RoutePrefix
		if artifact.pluginMarker {
			route = cfg.PluginRoutePrefix
		}
		validRoutes[artifact.Path] = route
	}
	for path, entry := range file.Completed {
		route, ok := validRoutes[path]
		if !ok {
			return nil, fmt.Errorf("prewarm checkpoint contains unknown artifact %q", path)
		}
		if entry.Status != "HIT" && entry.Status != "MISS" {
			return nil, fmt.Errorf("prewarm checkpoint contains invalid cache status %q for %s", entry.Status, path)
		}
		if entry.Route != route {
			return nil, fmt.Errorf("prewarm checkpoint contains route %q for %s, expected %q", entry.Route, path, route)
		}
		state.entries[path] = entry
	}
	return state, nil
}

func (c *checkpoint) completedArtifact(artifact Artifact) (checkpointEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[artifact.Path]
	return entry, ok
}

func (c *checkpoint) completed(artifact Artifact) (checkpointEntry, bool) {
	return c.completedArtifact(artifact)
}

func (c *checkpoint) record(artifact Artifact, route, status string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[artifact.Path] = checkpointEntry{Route: route, Status: status}
	return c.saveLocked()
}

func (c *checkpoint) saveLocked() error {
	file := checkpointFile{
		Version:        checkpointVersion,
		ManifestSHA256: c.manifestSHA256,
		Completed:      c.entries,
	}
	data, err := json.Marshal(file)
	if err != nil {
		return err
	}
	directory := filepath.Dir(c.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".package-firewall-prewarm-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, c.path)
}

func fingerprintManifest(cfg RunConfig, artifacts []Artifact) (string, error) {
	fingerprint := manifestFingerprint{
		BaseURL:           cfg.BaseURL,
		RoutePrefix:       cfg.RoutePrefix,
		PluginRoutePrefix: cfg.PluginRoutePrefix,
		Artifacts:         make([]artifactFingerprint, 0, len(artifacts)),
	}
	for _, artifact := range artifacts {
		fingerprint.Artifacts = append(fingerprint.Artifacts, artifactFingerprint{
			Coordinate:   artifact.Coordinate,
			Path:         artifact.Path,
			SHA256:       append([]string(nil), artifact.SHA256...),
			PluginMarker: artifact.pluginMarker,
		})
	}
	data, err := json.Marshal(fingerprint)
	if err != nil {
		return "", fmt.Errorf("encode prewarm manifest fingerprint: %w", err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}
