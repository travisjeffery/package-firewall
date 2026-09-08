package objectcache

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestFileSystemStoreRoundTripsEntry(t *testing.T) {
	store := NewFileSystemStore(t.TempDir())
	key := Key("GET", "npm", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")

	err := store.Put(context.Background(), PutRequest{
		Key:            key,
		StatusCode:     http.StatusOK,
		Headers:        http.Header{"Content-Type": []string{"application/octet-stream"}, "Set-Cookie": []string{"secret=1"}},
		Body:           strings.NewReader("artifact-body"),
		TTL:            time.Hour,
		StaleIfError:   24 * time.Hour,
		Immutable:      true,
		ContentLength:  int64(len("artifact-body")),
		ComputedSHA256: "sha256",
	})
	if err != nil {
		t.Fatal(err)
	}

	entry, ok, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected cache entry")
	}
	defer entry.Body.Close()
	body, err := io.ReadAll(entry.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "artifact-body" {
		t.Fatalf("body = %q", string(body))
	}
	if entry.Headers.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content-type = %q", entry.Headers.Get("Content-Type"))
	}
	if entry.Headers.Get("Set-Cookie") != "" {
		t.Fatalf("unsafe header persisted: %q", entry.Headers.Get("Set-Cookie"))
	}
	if !entry.Fresh(time.Now()) {
		t.Fatal("entry should be fresh")
	}
}
