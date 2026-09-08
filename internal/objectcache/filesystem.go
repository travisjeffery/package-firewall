package objectcache

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FileSystemStore struct {
	dir string
	now func() time.Time
}

func NewFileSystemStore(dir string) *FileSystemStore {
	return &FileSystemStore{
		dir: dir,
		now: time.Now,
	}
}

func (s *FileSystemStore) Get(_ context.Context, key string) (Entry, bool, error) {
	recordPath := s.recordPath(key)
	raw, err := os.ReadFile(recordPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Entry{}, false, nil
		}
		return Entry{}, false, err
	}
	var record fileRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return Entry{}, false, err
	}
	body, err := os.Open(s.bodyPath(key))
	if err != nil {
		if os.IsNotExist(err) {
			return Entry{}, false, nil
		}
		return Entry{}, false, err
	}
	return record.entry(key, body), true, nil
}

func (s *FileSystemStore) Put(_ context.Context, req PutRequest) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	bodyPath := s.bodyPath(req.Key)
	tmpBodyPath := bodyPath + ".tmp"
	out, err := os.OpenFile(tmpBodyPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, req.Body)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(tmpBodyPath)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpBodyPath)
		return closeErr
	}
	if err := os.Rename(tmpBodyPath, bodyPath); err != nil {
		_ = os.Remove(tmpBodyPath)
		return err
	}

	now := s.now().UTC()
	record := fileRecord{
		StatusCode:        req.StatusCode,
		Headers:           SafeHeaders(req.Headers),
		SHA256:            req.ComputedSHA256,
		Size:              req.ContentLength,
		FetchedAt:         now,
		ExpiresAt:         now.Add(req.TTL),
		StaleIfErrorUntil: now.Add(req.TTL + req.StaleIfError),
		Immutable:         req.Immutable,
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tmpRecordPath := s.recordPath(req.Key) + ".tmp"
	if err := os.WriteFile(tmpRecordPath, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpRecordPath, s.recordPath(req.Key))
}

func (s *FileSystemStore) recordPath(key string) string {
	return filepath.Join(s.dir, safeKey(key)+".json")
}

func (s *FileSystemStore) bodyPath(key string) string {
	return filepath.Join(s.dir, safeKey(key)+".body")
}

func safeKey(key string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, key)
}

type fileRecord struct {
	StatusCode        int         `json:"status_code"`
	Headers           http.Header `json:"headers"`
	SHA256            string      `json:"sha256"`
	Size              int64       `json:"size"`
	FetchedAt         time.Time   `json:"fetched_at"`
	ExpiresAt         time.Time   `json:"expires_at"`
	StaleIfErrorUntil time.Time   `json:"stale_if_error_until"`
	Immutable         bool        `json:"immutable"`
}

func (r fileRecord) entry(key string, body io.ReadCloser) Entry {
	return Entry{
		Key:               key,
		StatusCode:        r.StatusCode,
		Headers:           r.Headers,
		Body:              body,
		SHA256:            r.SHA256,
		Size:              r.Size,
		FetchedAt:         r.FetchedAt,
		ExpiresAt:         r.ExpiresAt,
		StaleIfErrorUntil: r.StaleIfErrorUntil,
		Immutable:         r.Immutable,
	}
}
