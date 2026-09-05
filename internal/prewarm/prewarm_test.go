package prewarm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunWarmsThenRequiresCacheHits(t *testing.T) {
	bodies := map[string]string{
		"/maven/org/example/library/1.0/library-1.0.jar": "jar-body",
		"/maven/org/example/library/1.0/library-1.0.pom": "pom-body",
	}
	var mu sync.Mutex
	hits := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, ok := bodies[request.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		hits[request.URL.Path]++
		attempt := hits[request.URL.Path]
		mu.Unlock()
		if attempt == 1 {
			w.Header().Set(cacheStatusHeader, "MISS")
		} else {
			w.Header().Set(cacheStatusHeader, "HIT")
		}
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	artifacts := []Artifact{
		{Path: "org/example/library/1.0/library-1.0.jar", SHA256: []string{sum("jar-body")}},
		{Path: "org/example/library/1.0/library-1.0.pom", SHA256: []string{sum("pom-body")}},
	}
	var output bytes.Buffer
	err := Run(context.Background(), RunConfig{
		BaseURL:     server.URL,
		Concurrency: 2,
		HTTPClient:  server.Client(),
		BearerToken: "test-token",
	}, artifacts, &output)
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != "pass=1 artifacts=2 cache_hits=0 cache_misses=2\npass=2 artifacts=2 cache_hits=2 cache_misses=0\n" {
		t.Fatalf("output = %q", output.String())
	}
	mu.Lock()
	defer mu.Unlock()
	for path := range bodies {
		if hits[path] != 2 {
			t.Fatalf("hits[%q] = %d want 2", path, hits[path])
		}
	}
}

func TestRunRetriesRateLimitedArtifact(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		attempt := requests
		mu.Unlock()
		if attempt == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if attempt == 2 {
			w.Header().Set(cacheStatusHeader, "MISS")
		} else {
			w.Header().Set(cacheStatusHeader, "HIT")
		}
		_, _ = io.WriteString(w, "artifact")
	}))
	defer server.Close()

	var output bytes.Buffer
	err := Run(context.Background(), RunConfig{
		BaseURL:          server.URL,
		Concurrency:      1,
		RateLimitRetries: 1,
		HTTPClient:       server.Client(),
	}, []Artifact{{Path: "org/example/library/1.0/library-1.0.jar", SHA256: []string{sum("artifact")}}}, &output)
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != "pass=1 artifacts=1 cache_hits=0 cache_misses=1\npass=2 artifacts=1 cache_hits=1 cache_misses=0\n" {
		t.Fatalf("output = %q", output.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 3 {
		t.Fatalf("requests = %d want 3", requests)
	}
}

func TestRunPassPacesFirstPassAcrossWorkers(t *testing.T) {
	const artifactCount = 4
	const interval = 50 * time.Millisecond
	var mu sync.Mutex
	var starts []time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		starts = append(starts, time.Now())
		mu.Unlock()
		w.Header().Set(cacheStatusHeader, "MISS")
		_, _ = io.WriteString(w, "artifact")
	}))
	defer server.Close()

	artifacts := make([]Artifact, 0, artifactCount)
	for index := range artifactCount {
		artifacts = append(artifacts, Artifact{
			Path:   fmt.Sprintf("org/example/library/%d/library-%d.jar", index, index),
			SHA256: []string{sum("artifact")},
		})
	}
	config, err := normalizeRunConfig(RunConfig{
		BaseURL:            server.URL,
		Concurrency:        artifactCount,
		MinRequestInterval: interval,
		HTTPClient:         server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runPass(context.Background(), config, artifacts, nil, false, nil); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(starts) != artifactCount {
		t.Fatalf("request count = %d want %d", len(starts), artifactCount)
	}
	sort.Slice(starts, func(left, right int) bool { return starts[left].Before(starts[right]) })
	minimum := interval - 10*time.Millisecond
	for index := 1; index < len(starts); index++ {
		if spacing := starts[index].Sub(starts[index-1]); spacing < minimum {
			t.Fatalf("request spacing = %s want at least %s", spacing, minimum)
		}
	}
}

func TestRunRejectsNegativeMinRequestInterval(t *testing.T) {
	err := Run(context.Background(), RunConfig{
		BaseURL:            "https://packages.example",
		MinRequestInterval: -time.Second,
	}, []Artifact{{Path: "artifact", SHA256: []string{sum("artifact")}}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "minimum request interval") {
		t.Fatalf("error = %v", err)
	}
}

func TestNormalizeDefaultsToOneRateLimitRetry(t *testing.T) {
	config, err := normalizeRunConfig(RunConfig{BaseURL: "https://packages.example"})
	if err != nil {
		t.Fatal(err)
	}
	if config.RateLimitRetries != 1 {
		t.Fatalf("rate-limit retries = %d want 1", config.RateLimitRetries)
	}
}

func TestRunResumesFromCheckpoint(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "prewarm-state.json")
	var mu sync.Mutex
	requests := make(map[string]int)
	failSecond := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests[request.URL.Path]++
		attempt := requests[request.URL.Path]
		shouldFail := failSecond && strings.HasSuffix(request.URL.Path, "two.jar")
		mu.Unlock()
		if shouldFail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		if attempt == 1 {
			w.Header().Set(cacheStatusHeader, "MISS")
		} else {
			w.Header().Set(cacheStatusHeader, "HIT")
		}
		_, _ = io.WriteString(w, strings.TrimSuffix(filepath.Base(request.URL.Path), ".jar"))
	}))
	defer server.Close()
	artifacts := []Artifact{
		{Path: "org/example/library/1.0/one.jar", SHA256: []string{sum("one")}},
		{Path: "org/example/library/1.0/two.jar", SHA256: []string{sum("two")}},
	}
	cfg := RunConfig{BaseURL: server.URL, Concurrency: 1, StateFile: stateFile, HTTPClient: server.Client()}
	if err := Run(context.Background(), cfg, artifacts, io.Discard); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("first run error = %v", err)
	}
	data, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var file checkpointFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Completed) != 1 || file.Completed[artifacts[0].Path].Status != "MISS" {
		t.Fatalf("checkpoint = %#v", file)
	}

	mu.Lock()
	failSecond = false
	mu.Unlock()
	if err := Run(context.Background(), cfg, artifacts, io.Discard); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	firstPath := "/maven/" + artifacts[0].Path
	secondPath := "/maven/" + artifacts[1].Path
	if requests[firstPath] != 2 {
		t.Fatalf("resumed first artifact requests = %d want 2", requests[firstPath])
	}
	if requests[secondPath] != 3 {
		t.Fatalf("resumed second artifact requests = %d want 3", requests[secondPath])
	}
}

func TestRunRejectsWarmPassMiss(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(cacheStatusHeader, "MISS")
		_, _ = io.WriteString(w, "artifact")
	}))
	defer server.Close()
	err := Run(context.Background(), RunConfig{BaseURL: server.URL, Concurrency: 1, HTTPClient: server.Client()}, []Artifact{{
		Path:   "org/example/library/1.0/library-1.0.jar",
		SHA256: []string{sum("artifact")},
	}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "second pass returned cache status \"MISS\", expected HIT") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunUsesOnlyTheDeclaredArtifactRouteOnBothPasses(t *testing.T) {
	bodies := map[string]string{
		"/maven/org/example/library/1.0/library-1.0.jar":                                     "library",
		"/gradle-plugins/com/example/plugin/com.example.plugin.gradle.plugin/1.0/marker.pom": "marker",
		"/maven/com/example/implementation/1.0/implementation-1.0.jar":                       "implementation",
	}
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests[request.URL.Path]++
		attempt := requests[request.URL.Path]
		mu.Unlock()
		body, ok := bodies[request.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if attempt == 1 {
			w.Header().Set(cacheStatusHeader, "MISS")
		} else {
			w.Header().Set(cacheStatusHeader, "HIT")
		}
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	err := Run(context.Background(), RunConfig{
		BaseURL:           server.URL,
		RoutePrefix:       "/maven/",
		PluginRoutePrefix: "/gradle-plugins/",
		Concurrency:       2,
		HTTPClient:        server.Client(),
	}, []Artifact{
		{Coordinate: "org.example:library:1.0", Path: "org/example/library/1.0/library-1.0.jar", SHA256: []string{sum("library")}},
		{Coordinate: "com.example.plugin:com.example.plugin.gradle.plugin:1.0", Path: "com/example/plugin/com.example.plugin.gradle.plugin/1.0/marker.pom", SHA256: []string{sum("marker")}, pluginMarker: true},
		{Coordinate: "com.example:implementation:1.0", Path: "com/example/implementation/1.0/implementation-1.0.jar", SHA256: []string{sum("implementation")}},
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if requests["/maven/com/example/plugin/com.example.plugin.gradle.plugin/1.0/marker.pom"] != 0 {
		t.Fatalf("plugin marker was requested from Maven: %#v", requests)
	}
	if requests["/gradle-plugins/com/example/implementation/1.0/implementation-1.0.jar"] != 0 {
		t.Fatalf("ordinary artifact was requested from the Plugin Portal route: %#v", requests)
	}
	for path := range bodies {
		if requests[path] != 2 {
			t.Fatalf("requests[%q] = %d want 2", path, requests[path])
		}
	}
}

func TestRunDoesNotFallbackOrdinaryArtifactsToPluginRoute(t *testing.T) {
	var mu sync.Mutex
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mu.Lock()
		requests[request.URL.Path]++
		mu.Unlock()
		if strings.HasPrefix(request.URL.Path, "/gradle-plugins/") {
			w.Header().Set(cacheStatusHeader, "MISS")
			_, _ = io.WriteString(w, "implementation")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	err := Run(context.Background(), RunConfig{
		BaseURL:           server.URL,
		RoutePrefix:       "/maven/",
		PluginRoutePrefix: "/gradle-plugins/",
		Concurrency:       1,
		HTTPClient:        server.Client(),
	}, []Artifact{{
		Coordinate: "com.example:implementation:1.0",
		Path:       "com/example/implementation/1.0/implementation-1.0.jar",
		SHA256:     []string{sum("implementation")},
	}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "unavailable from configured Package Firewall routes") {
		t.Fatalf("error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests["/maven/com/example/implementation/1.0/implementation-1.0.jar"] != 1 || requests["/gradle-plugins/com/example/implementation/1.0/implementation-1.0.jar"] != 0 {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestRunRequiresPluginRouteForSelectedMarkers(t *testing.T) {
	err := Run(context.Background(), RunConfig{
		BaseURL:     "https://packages.example",
		RoutePrefix: "/maven/",
	}, []Artifact{{
		Coordinate:   "com.example:com.example.gradle.plugin:1.0",
		Path:         "com/example/com.example.gradle.plugin/1.0/marker.pom",
		SHA256:       []string{sum("marker")},
		pluginMarker: true,
	}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "plugin route prefix is required") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunReportsAllArtifactsUnavailableFromConfiguredRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	err := Run(context.Background(), RunConfig{
		BaseURL:           server.URL,
		RoutePrefix:       "/maven/",
		PluginRoutePrefix: "/gradle-plugins/",
		Concurrency:       2,
		HTTPClient:        server.Client(),
	}, []Artifact{
		{Coordinate: "com.example:one:1.0", Path: "com/example/one/1.0/one.jar", SHA256: []string{sum("one")}},
		{Coordinate: "com.example:two:2.0", Path: "com/example/two/2.0/two.jar", SHA256: []string{sum("two")}},
	}, io.Discard)
	if err == nil {
		t.Fatal("prewarm unexpectedly succeeded")
	}
	for _, want := range []string{"2 artifacts across 2 coordinates", "com.example:one:1.0", "com.example:two:2.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestRunRejectsDuplicateRoutes(t *testing.T) {
	err := Run(context.Background(), RunConfig{
		BaseURL:           "https://packages.example",
		RoutePrefix:       "/maven/",
		PluginRoutePrefix: "/maven",
	}, []Artifact{{Path: "artifact", SHA256: []string{sum("artifact")}}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunRejectsChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(cacheStatusHeader, "MISS")
		_, _ = io.WriteString(w, "different")
	}))
	defer server.Close()
	err := Run(context.Background(), RunConfig{BaseURL: server.URL, Concurrency: 1, HTTPClient: server.Client()}, []Artifact{{
		Path:   "org/example/library/1.0/library-1.0.jar",
		SHA256: []string{sum("artifact")},
	}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunBoundsPrewarmConcurrency(t *testing.T) {
	const artifactCount = 6
	var inFlight atomic.Int32
	var maximum atomic.Int32
	started := make(chan struct{}, artifactCount)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	var mu sync.Mutex
	hits := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		current := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		mu.Lock()
		hits[request.URL.Path]++
		attempt := hits[request.URL.Path]
		mu.Unlock()
		if attempt == 1 {
			started <- struct{}{}
			<-release
			w.Header().Set(cacheStatusHeader, "MISS")
		} else {
			w.Header().Set(cacheStatusHeader, "HIT")
		}
		_, _ = io.WriteString(w, "artifact")
	}))
	defer server.Close()
	artifacts := make([]Artifact, 0, artifactCount)
	for index := range artifactCount {
		artifacts = append(artifacts, Artifact{
			Path:   "org/example/library/1.0/library-1.0-" + string(rune('a'+index)) + ".jar",
			SHA256: []string{sum("artifact")},
		})
	}
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), RunConfig{BaseURL: server.URL, Concurrency: 2, HTTPClient: server.Client()}, artifacts, io.Discard)
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("two prewarm requests did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("prewarm exceeded its concurrency limit")
	case <-time.After(50 * time.Millisecond):
	}
	releaseAll()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != 2 {
		t.Fatalf("maximum concurrency = %d want 2", maximum.Load())
	}
}

func TestRunDoesNotForwardCredentialsAcrossRedirectOrigins(t *testing.T) {
	var received atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "" {
			received.Store(true)
		}
		_, _ = io.WriteString(w, "artifact")
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, target.URL+request.URL.Path, http.StatusFound)
	}))
	defer source.Close()
	err := Run(context.Background(), RunConfig{
		BaseURL:     source.URL,
		Concurrency: 1,
		HTTPClient:  source.Client(),
		BearerToken: "test-token",
	}, []Artifact{{Path: "org/example/library/1.0/library-1.0.jar", SHA256: []string{sum("artifact")}}}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "redirect changed origin") {
		t.Fatalf("error = %v", err)
	}
	if received.Load() {
		t.Fatal("credential reached the redirect target")
	}
}

func TestRunReturnsParentCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, RunConfig{BaseURL: "https://packages.example", Concurrency: 1}, []Artifact{{
		Path:   "org/example/library/1.0/library-1.0.jar",
		SHA256: []string{sum("artifact")},
	}}, io.Discard)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func sum(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
