package artifactcache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestFileSystemStoreRoundTripAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	store := NewFileSystemStore(t.TempDir())
	store.now = func() time.Time { return now }
	body := []byte("artifact-body")
	key := Key("npm", "pkg", "1.0.0")
	if err := store.Put(context.Background(), key, PutRequest{
		Headers: http.Header{
			"Content-Type": []string{"application/octet-stream"},
			"ETag":         []string{`"artifact-v1"`},
			"Set-Cookie":   []string{"secret=value"},
		},
		Body:      bytes.NewReader(body),
		SHA256:    digestBytes(body),
		Size:      int64(len(body)),
		StoredAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	entry, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	readBody, err := io.ReadAll(entry.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := entry.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readBody, body) || entry.Size != int64(len(body)) || entry.SHA256 != digestBytes(body) {
		t.Fatalf("entry = size %d sha %q body %q", entry.Size, entry.SHA256, readBody)
	}
	if !entry.StoredAt.Equal(now) {
		t.Fatalf("stored at = %s want %s", entry.StoredAt, now)
	}
	if entry.Headers.Get("Content-Type") != "application/octet-stream" || entry.Headers.Get("ETag") != `"artifact-v1"` {
		t.Fatalf("headers = %#v", entry.Headers)
	}
	if entry.Headers.Get("Set-Cookie") != "" {
		t.Fatalf("unsafe header was stored: %#v", entry.Headers)
	}

	store.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := store.Get(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired get error = %v", err)
	}
}

func TestFileSystemStoreDoesNotReplaceGoodEntryWithPartialPut(t *testing.T) {
	store := NewFileSystemStore(t.TempDir())
	key := Key("npm", "pkg", "1.0.0")
	expiresAt := time.Now().Add(time.Hour)
	oldBody := []byte("known-good")
	if err := store.Put(context.Background(), key, PutRequest{
		Body:      bytes.NewReader(oldBody),
		SHA256:    digestBytes(oldBody),
		Size:      int64(len(oldBody)),
		StoredAt:  expiresAt.Add(-time.Hour),
		ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), key, PutRequest{
		Body:      strings.NewReader("short"),
		SHA256:    digestBytes([]byte("expected-body")),
		Size:      int64(len("expected-body")),
		StoredAt:  expiresAt.Add(-time.Hour),
		ExpiresAt: expiresAt,
	}); err == nil {
		t.Fatal("partial put succeeded")
	}
	entry, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Body.Close()
	got, err := io.ReadAll(entry.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, oldBody) {
		t.Fatalf("good entry was replaced with %q", got)
	}
}

func TestCopyExactlyDoesNotWritePastDeclaredSize(t *testing.T) {
	var destination bytes.Buffer
	written, err := copyExactly(context.Background(), &destination, strings.NewReader("oversized"), 4)
	if err == nil {
		t.Fatal("oversized source succeeded")
	}
	if written != 4 || destination.Len() != 4 || destination.String() != "over" {
		t.Fatalf("written = %d destination = %q", written, destination.String())
	}
}

func TestFileSystemStoreRejectsInvalidKey(t *testing.T) {
	store := NewFileSystemStore(t.TempDir())
	_, err := store.Get(context.Background(), "../../escape")
	if !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("error = %v", err)
	}
}

func digestBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
