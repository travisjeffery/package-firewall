package artifactcache

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	fileMagic         = "PFWART1\n"
	maxFileRecordSize = 64 << 10
)

var cacheKeyPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type FileSystemStore struct {
	directory string
	now       func() time.Time
}

func NewFileSystemStore(directory string) *FileSystemStore {
	return &FileSystemStore{directory: directory, now: time.Now}
}

func (s *FileSystemStore) Get(ctx context.Context, key string) (Entry, error) {
	if err := validateKey(key); err != nil {
		return Entry{}, err
	}
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	file, err := os.Open(s.entryPath(key))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Entry{}, ErrNotFound
		}
		return Entry{}, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()

	magic := make([]byte, len(fileMagic))
	if _, err := io.ReadFull(file, magic); err != nil {
		return Entry{}, errors.Join(ErrInvalidEntry, fmt.Errorf("read filesystem cache magic: %w", err))
	}
	if string(magic) != fileMagic {
		return Entry{}, errors.Join(ErrInvalidEntry, errors.New("invalid filesystem cache magic"))
	}
	var recordSize uint32
	if err := binary.Read(file, binary.BigEndian, &recordSize); err != nil {
		return Entry{}, errors.Join(ErrInvalidEntry, err)
	}
	if recordSize == 0 || recordSize > maxFileRecordSize {
		return Entry{}, errors.Join(ErrInvalidEntry, fmt.Errorf("invalid record size %d", recordSize))
	}
	recordBytes := make([]byte, recordSize)
	if _, err := io.ReadFull(file, recordBytes); err != nil {
		return Entry{}, errors.Join(ErrInvalidEntry, err)
	}
	var record fileRecord
	if err := json.Unmarshal(recordBytes, &record); err != nil {
		return Entry{}, errors.Join(ErrInvalidEntry, err)
	}
	entry := Entry{
		Headers:   SafeHeaders(record.Headers),
		Body:      file,
		SHA256:    record.SHA256,
		Size:      record.Size,
		ExpiresAt: record.ExpiresAt,
	}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, err
	}
	if entry.Expired(s.now()) {
		return Entry{}, ErrNotFound
	}
	stat, err := file.Stat()
	if err != nil {
		return Entry{}, err
	}
	bodyOffset := int64(len(fileMagic) + 4 + len(recordBytes))
	if stat.Size() != bodyOffset+entry.Size {
		return Entry{}, errors.Join(ErrInvalidEntry, fmt.Errorf("file size %d does not match metadata size %d", stat.Size(), entry.Size))
	}
	closeOnError = false
	entry.Body = &limitedReadCloser{Reader: io.LimitReader(file, entry.Size), Closer: file}
	return entry, nil
}

func (s *FileSystemStore) Put(ctx context.Context, key string, req PutRequest) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := ValidatePut(req); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	directory := filepath.Dir(s.entryPath(key))
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	recordBytes, err := json.Marshal(fileRecord{
		Headers:   SafeHeaders(req.Headers),
		SHA256:    req.SHA256,
		Size:      req.Size,
		ExpiresAt: req.ExpiresAt.UTC(),
	})
	if err != nil {
		return err
	}
	if len(recordBytes) == 0 || len(recordBytes) > maxFileRecordSize {
		return fmt.Errorf("filesystem cache metadata is %d bytes; maximum is %d", len(recordBytes), maxFileRecordSize)
	}

	temporary, err := os.CreateTemp(directory, ".pfw-cache-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.WriteString(temporary, fileMagic); err != nil {
		return err
	}
	if err := binary.Write(temporary, binary.BigEndian, uint32(len(recordBytes))); err != nil {
		return err
	}
	if _, err := temporary.Write(recordBytes); err != nil {
		return err
	}
	hasher := sha256.New()
	written, err := copyExactly(ctx, io.MultiWriter(temporary, hasher), req.Body, req.Size)
	if err != nil {
		return err
	}
	if written != req.Size {
		return fmt.Errorf("filesystem cache body size %d does not match expected size %d", written, req.Size)
	}
	if computed := hex.EncodeToString(hasher.Sum(nil)); computed != req.SHA256 {
		return fmt.Errorf("filesystem cache body checksum %s does not match expected checksum %s", computed, req.SHA256)
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, s.entryPath(key)); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func (s *FileSystemStore) entryPath(key string) string {
	shard := "invalid"
	if len(key) >= 2 {
		shard = key[:2]
	}
	return filepath.Join(s.directory, "v1", shard, key+".artifact")
}

func validateKey(key string) error {
	if !cacheKeyPattern.MatchString(key) {
		return fmt.Errorf("%w: invalid cache key", ErrInvalidEntry)
	}
	return nil
}

func copyExactly(ctx context.Context, dst io.Writer, src io.Reader, size int64) (int64, error) {
	buffer := make([]byte, 32<<10)
	var written int64
	for written < size {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		want := int64(len(buffer))
		if remaining := size - written; remaining < want {
			want = remaining
		}
		read, readErr := src.Read(buffer[:want])
		if read > 0 {
			count, writeErr := dst.Write(buffer[:read])
			written += int64(count)
			if writeErr != nil {
				return written, writeErr
			}
			if count != read {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && written == size {
				break
			}
			return written, readErr
		}
		if read == 0 {
			return written, io.ErrNoProgress
		}
	}
	var extra [1]byte
	read, err := src.Read(extra[:])
	if read > 0 {
		return written, fmt.Errorf("body exceeds expected size %d", size)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return written, err
	}
	return written, nil
}

type fileRecord struct {
	Headers   http.Header `json:"headers"`
	SHA256    string      `json:"sha256"`
	Size      int64       `json:"size"`
	ExpiresAt time.Time   `json:"expires_at"`
}

type limitedReadCloser struct {
	io.Reader
	io.Closer
}
