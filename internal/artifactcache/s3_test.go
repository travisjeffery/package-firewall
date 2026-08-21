package artifactcache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestS3StoreRoundTripMetadata(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	client := &fakeS3API{}
	store := NewS3Store(S3Config{
		Client:              client,
		Bucket:              "artifact-cache",
		Prefix:              "package-firewall/cache",
		ExpectedBucketOwner: "123456789012",
	})
	store.now = func() time.Time { return now }
	body := []byte("artifact-body")
	key := Key("npm", "pkg", "1.0.0")
	request := PutRequest{
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
	}
	if err := store.Put(context.Background(), key, request); err != nil {
		t.Fatal(err)
	}
	if client.putInput == nil {
		t.Fatal("PutObject was not called")
	}
	if got := aws.ToString(client.putInput.Bucket); got != "artifact-cache" {
		t.Fatalf("bucket = %q", got)
	}
	wantKey := "package-firewall/cache/v1/" + key[:2] + "/" + key + ".artifact"
	if got := aws.ToString(client.putInput.Key); got != wantKey {
		t.Fatalf("key = %q want %q", got, wantKey)
	}
	if got := aws.ToString(client.putInput.ExpectedBucketOwner); got != "123456789012" {
		t.Fatalf("expected bucket owner = %q", got)
	}
	if !bytes.Equal(client.putBody, body) {
		t.Fatalf("put body = %q", client.putBody)
	}
	if client.putInput.Metadata["pfw-sha256"] != request.SHA256 || client.putInput.Metadata["pfw-version"] != s3MetadataVersion {
		t.Fatalf("metadata = %#v", client.putInput.Metadata)
	}

	client.getOutput = &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: aws.Int64(int64(len(body))),
		Metadata:      client.putInput.Metadata,
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
	if !bytes.Equal(readBody, body) || entry.SHA256 != request.SHA256 || entry.Size != int64(len(body)) {
		t.Fatalf("entry = size %d sha %q body %q", entry.Size, entry.SHA256, readBody)
	}
	if !entry.StoredAt.Equal(now) {
		t.Fatalf("stored at = %s want %s", entry.StoredAt, now)
	}
	if entry.Headers.Get("ETag") != `"artifact-v1"` || entry.Headers.Get("Set-Cookie") != "" {
		t.Fatalf("headers = %#v", entry.Headers)
	}
	if got := aws.ToString(client.getInput.ExpectedBucketOwner); got != "123456789012" {
		t.Fatalf("get expected bucket owner = %q", got)
	}
}

func TestS3StoreTreatsMissingAndExpiredObjectsAsMisses(t *testing.T) {
	client := &fakeS3API{getErr: &types.NoSuchKey{}}
	store := NewS3Store(S3Config{Client: client, Bucket: "artifact-cache"})
	key := Key("npm", "pkg", "1.0.0")
	if _, err := store.Get(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing object error = %v", err)
	}

	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	closed := false
	client.getErr = nil
	client.getOutput = &s3.GetObjectOutput{
		Body:          &trackingReadCloser{Reader: strings.NewReader("artifact"), closed: &closed},
		ContentLength: aws.Int64(8),
		Metadata: map[string]string{
			"pfw-version":    s3MetadataVersion,
			"pfw-sha256":     digestBytes([]byte("artifact")),
			"pfw-stored-at":  now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			"pfw-expires-at": now.Add(-time.Minute).Format(time.RFC3339Nano),
			"pfw-headers":    mustEncodeHeaders(t, http.Header{}),
		},
	}
	store.now = func() time.Time { return now }
	if _, err := store.Get(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired object error = %v", err)
	}
	if !closed {
		t.Fatal("expired S3 body was not closed")
	}
}

func TestS3StoreRejectsOversizedHeaderMetadataBeforePut(t *testing.T) {
	client := &fakeS3API{}
	store := NewS3Store(S3Config{Client: client, Bucket: "artifact-cache"})
	body := []byte("artifact")
	err := store.Put(context.Background(), Key("npm", "pkg", "1.0.0"), PutRequest{
		Headers:   http.Header{"Content-Disposition": []string{strings.Repeat("x", maxS3HeaderMetadataSize)}},
		Body:      bytes.NewReader(body),
		SHA256:    digestBytes(body),
		Size:      int64(len(body)),
		StoredAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("oversized S3 metadata was accepted")
	}
	if client.putInput != nil {
		t.Fatal("PutObject was called with oversized metadata")
	}
}

func TestS3StorePreservesConfiguredPrefixBytes(t *testing.T) {
	key := Key("npm", "pkg", "1.0.0")
	store := NewS3Store(S3Config{Prefix: "/nested//./artifacts/"})
	want := "nested//./artifacts/v1/" + key[:2] + "/" + key + ".artifact"
	if got := store.objectKey(key); got != want {
		t.Fatalf("object key = %q want %q", got, want)
	}
}

func mustEncodeHeaders(t *testing.T, headers http.Header) string {
	t.Helper()
	encoded, err := encodeS3Headers(headers)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type fakeS3API struct {
	getInput  *s3.GetObjectInput
	getOutput *s3.GetObjectOutput
	getErr    error
	putInput  *s3.PutObjectInput
	putBody   []byte
	putErr    error
}

func (f *fakeS3API) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.getInput = input
	return f.getOutput, f.getErr
}

func (f *fakeS3API) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.putInput = input
	if input.Body != nil {
		body, err := io.ReadAll(input.Body)
		if err != nil {
			return nil, err
		}
		f.putBody = body
	}
	return &s3.PutObjectOutput{}, f.putErr
}

type trackingReadCloser struct {
	io.Reader
	closed *bool
}

func (r *trackingReadCloser) Close() error {
	*r.closed = true
	return nil
}
