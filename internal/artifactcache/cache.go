package artifactcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	ErrNotFound     = errors.New("artifact cache entry not found")
	ErrInvalidEntry = errors.New("invalid artifact cache entry")
)

type Entry struct {
	Headers   http.Header
	Body      io.ReadCloser
	SHA256    string
	Size      int64
	StoredAt  time.Time
	ExpiresAt time.Time
}

func (e Entry) Expired(now time.Time) bool {
	return !e.ExpiresAt.After(now)
}

type PutRequest struct {
	Headers   http.Header
	Body      io.Reader
	SHA256    string
	Size      int64
	StoredAt  time.Time
	ExpiresAt time.Time
}

type Store interface {
	Get(ctx context.Context, key string) (Entry, error)
	Put(ctx context.Context, key string, req PutRequest) error
}

func Key(parts ...string) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("package-firewall-artifact-cache-v1"))
	for _, part := range parts {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(part))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func SafeHeaders(headers http.Header) http.Header {
	safe := make(http.Header)
	for key, values := range headers {
		switch strings.ToLower(key) {
		case "age", "cache-control", "content-disposition", "content-type", "date", "digest", "etag", "last-modified", "vary":
			for _, value := range values {
				safe.Add(key, value)
			}
		}
	}
	return safe
}

func ValidatePut(req PutRequest) error {
	if req.Body == nil {
		return errors.Join(ErrInvalidEntry, errors.New("body is required"))
	}
	if req.Size < 0 {
		return errors.Join(ErrInvalidEntry, errors.New("size cannot be negative"))
	}
	if !validSHA256(req.SHA256) {
		return errors.Join(ErrInvalidEntry, errors.New("sha256 must be a 64-character hexadecimal digest"))
	}
	if req.StoredAt.IsZero() {
		return errors.Join(ErrInvalidEntry, errors.New("stored_at is required"))
	}
	if req.ExpiresAt.IsZero() {
		return errors.Join(ErrInvalidEntry, errors.New("expires_at is required"))
	}
	if !req.ExpiresAt.After(req.StoredAt) {
		return errors.Join(ErrInvalidEntry, errors.New("expires_at must be after stored_at"))
	}
	return nil
}

func ValidateEntry(entry Entry) error {
	if entry.Body == nil {
		return errors.Join(ErrInvalidEntry, errors.New("body is required"))
	}
	return ValidatePut(PutRequest{
		Body:      entry.Body,
		SHA256:    entry.SHA256,
		Size:      entry.Size,
		StoredAt:  entry.StoredAt,
		ExpiresAt: entry.ExpiresAt,
	})
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
