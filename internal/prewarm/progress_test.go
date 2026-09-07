package prewarm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func progressEvents(t *testing.T, output *bytes.Buffer) []progressEvent {
	t.Helper()
	var events []progressEvent
	decoder := json.NewDecoder(output)
	for {
		var event progressEvent
		if err := decoder.Decode(&event); err == io.EOF {
			return events
		} else if err != nil {
			t.Fatal(err)
		}
		if event.Time.IsZero() {
			t.Fatal("missing timestamp")
		}
		events = append(events, event)
	}
}

func TestProgressReportsRequestPhasesAndVerifiedCompletion(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("missing authentication")
		}
		time.Sleep(15 * time.Millisecond)
		w.Header().Set(cacheStatusHeader, "HIT")
		w.Header().Set("X-Request-ID", "trace-id")
		w.Header().Set("Set-Cookie", "private-cookie")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(15 * time.Millisecond)
		_, _ = io.WriteString(w, "artifact")
		calls.Add(1)
	}))
	defer server.Close()
	var output, summary bytes.Buffer
	err := Run(context.Background(), RunConfig{
		BaseURL: server.URL, Progress: &output, BearerToken: "private-token",
	}, []Artifact{{Path: "a.jar", SHA256: []string{sum("artifact")}}}, &summary)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || strings.Contains(output.String(), "private-token") || strings.Contains(output.String(), "private-cookie") || strings.Contains(output.String(), server.URL) {
		t.Fatal("unexpected request count or sensitive progress data")
	}
	events := progressEvents(t, &output)
	for pass := 1; pass <= 2; pass++ {
		var phases []string
		for _, event := range events {
			if event.Pass != pass {
				continue
			}
			phases = append(phases, event.Event)
			if event.Event == "request_end" {
				if event.HeadersMS < 10 || event.BodyMS < 10 || event.ElapsedMS < event.HeadersMS+event.BodyMS || event.Bytes != 8 || event.HTTPStatus != 200 || event.RequestID != "trace-id" || event.Outcome != "verified" || event.Attempt != 1 {
					t.Fatalf("bad timing/result: %+v", event)
				}
			}
			if event.Event == "artifact_complete" && (event.Completed != 1 || event.Total != 1 || event.CacheStatus != "HIT") {
				t.Fatalf("bad completion: %+v", event)
			}
			if event.Event == "pass_end" {
				if event.Requests != 1 || event.Retries != 0 || event.RetryWaitMS != 0 || event.Completed != 1 || event.HeadersMS < 10 || event.BodyMS < 10 || event.ElapsedMS < event.HeadersMS+event.BodyMS {
					t.Fatalf("bad pass totals: %+v", event)
				}
			}
		}
		if strings.Join(phases, ",") != "pass_start,artifact_start,request_start,request_sent,request_headers,request_end,artifact_complete,pass_end" {
			t.Fatalf("phases = %v", phases)
		}
	}
}

type progressWriterFunc func([]byte) (int, error)

func (f progressWriterFunc) Write(p []byte) (int, error) { return f(p) }

func TestProgressReportsLongRetryBeforeWaitingAndHonorsCancellation(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1800")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var retry, passEnd progressEvent
	writer := progressWriterFunc(func(p []byte) (int, error) {
		var event progressEvent
		if err := json.Unmarshal(p, &event); err != nil {
			t.Error(err)
		}
		switch event.Event {
		case "retry_wait":
			retry = event
			cancel()
		case "pass_end":
			passEnd = event
		}
		return len(p), nil
	})
	err := Run(ctx, RunConfig{BaseURL: server.URL, Progress: writer}, []Artifact{{Path: "a.jar", SHA256: []string{sum("artifact")}}}, nil)
	if !errors.Is(err, context.Canceled) || retry.RetryDelayMS != 1800000 || !retry.RetryAfter || retry.Attempt != 1 || calls.Load() != 1 {
		t.Fatalf("error=%v retry=%+v calls=%d", err, retry, calls.Load())
	}
	if passEnd.Retries != 1 || passEnd.RetryWaitMS != 1800000 || passEnd.Completed != 0 {
		t.Fatalf("pass totals did not attribute the upstream cooldown: %+v", passEnd)
	}
}

func TestProgressSeparatesPacingAndSerializesWorkers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(cacheStatusHeader, "HIT")
		_, _ = io.WriteString(w, "artifact")
	}))
	defer server.Close()
	var output bytes.Buffer
	artifacts := []Artifact{{Path: "a.jar", SHA256: []string{sum("artifact")}}, {Path: "b.jar", SHA256: []string{sum("artifact")}}}
	err := Run(context.Background(), RunConfig{BaseURL: server.URL, Concurrency: 2, MinRequestInterval: 30 * time.Millisecond, Progress: &output}, artifacts, nil)
	if err != nil {
		t.Fatal(err)
	}
	var paced, completed int
	for _, event := range progressEvents(t, &output) {
		if event.Event == "request_sent" && event.Pass == 1 && event.PacingMS >= 20 {
			paced++
		}
		if event.Event == "artifact_complete" {
			completed++
		}
	}
	if paced == 0 || completed != 4 {
		t.Fatalf("paced=%d completed=%d", paced, completed)
	}
}

func TestProgressReportsFailuresWithoutBodies(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusOK} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "private response body")
			}))
			defer server.Close()
			var output bytes.Buffer
			err := Run(context.Background(), RunConfig{BaseURL: server.URL, Progress: &output}, []Artifact{{Path: "a.jar", SHA256: []string{sum("artifact")}}}, nil)
			if err == nil || strings.Contains(output.String(), "private response body") {
				t.Fatal("expected failure without response body")
			}
			var requestEnd, artifactFailed bool
			for _, event := range progressEvents(t, &output) {
				requestEnd = requestEnd || event.Event == "request_end" && event.HTTPStatus == status && event.Outcome != "verified"
				artifactFailed = artifactFailed || event.Event == "artifact_failed"
			}
			if !requestEnd || !artifactFailed {
				t.Fatal("missing failure events")
			}
		})
	}
}

func TestProgressWriterFailureIsReturned(t *testing.T) {
	writeErr := errors.New("progress writer failed")
	writer := progressWriterFunc(func([]byte) (int, error) { return 0, writeErr })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(cacheStatusHeader, "HIT")
		_, _ = io.WriteString(w, "artifact")
	}))
	defer server.Close()
	err := Run(context.Background(), RunConfig{BaseURL: server.URL, Progress: writer}, []Artifact{{Path: "a.jar", SHA256: []string{sum("artifact")}}}, nil)
	if !errors.Is(err, writeErr) {
		t.Fatalf("writer error = %v", err)
	}
}
