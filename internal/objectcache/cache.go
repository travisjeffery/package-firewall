package objectcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

type Entry struct {
	Key               string
	StatusCode        int
	Headers           http.Header
	Body              io.ReadCloser
	SHA256            string
	Size              int64
	FetchedAt         time.Time
	ExpiresAt         time.Time
	StaleIfErrorUntil time.Time
	Immutable         bool
}

func (e Entry) Fresh(now time.Time) bool {
	return e.ExpiresAt.IsZero() || !now.After(e.ExpiresAt)
}

func (e Entry) CanServeOnError(now time.Time) bool {
	return e.Immutable || e.StaleIfErrorUntil.IsZero() || !now.After(e.StaleIfErrorUntil)
}

type PutRequest struct {
	Key            string
	StatusCode     int
	Headers        http.Header
	Body           io.Reader
	TTL            time.Duration
	StaleIfError   time.Duration
	Immutable      bool
	ContentLength  int64
	ComputedSHA256 string
}

type Store interface {
	Get(ctx context.Context, key string) (Entry, bool, error)
	Put(ctx context.Context, req PutRequest) error
}

func Key(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func SafeHeaders(headers http.Header) http.Header {
	safe := http.Header{}
	for key, values := range headers {
		switch strings.ToLower(key) {
		case "content-type", "content-length", "etag", "last-modified", "cache-control", "accept-ranges", "x-checksum-sha256", "x-amz-meta-sha256":
			for _, value := range values {
				safe.Add(key, value)
			}
		}
	}
	return safe
}
