package prewarm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
