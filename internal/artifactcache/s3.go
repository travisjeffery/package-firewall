package artifactcache

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const (
	s3MetadataVersion       = "2"
	maxS3HeaderMetadataSize = 1400
)

type S3API interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

type S3Config struct {
	Client              S3API
	Bucket              string
	Prefix              string
	ExpectedBucketOwner string
}

type S3Store struct {
	client              S3API
	bucket              string
	prefix              string
	expectedBucketOwner string
	now                 func() time.Time
}

func NewS3Store(cfg S3Config) *S3Store {
	return &S3Store{
		client:              cfg.Client,
		bucket:              cfg.Bucket,
		prefix:              strings.Trim(cfg.Prefix, "/"),
		expectedBucketOwner: cfg.ExpectedBucketOwner,
		now:                 time.Now,
	}
}

func (s *S3Store) Get(ctx context.Context, key string) (Entry, error) {
	if err := validateKey(key); err != nil {
		return Entry{}, err
	}
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.objectKey(key)),
	}
	if s.expectedBucketOwner != "" {
		input.ExpectedBucketOwner = aws.String(s.expectedBucketOwner)
	}
	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		if isS3NotFound(err) {
			return Entry{}, ErrNotFound
		}
		return Entry{}, err
	}
	if output.Body == nil {
		return Entry{}, errors.Join(ErrInvalidEntry, errors.New("S3 object body is missing"))
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = output.Body.Close()
		}
	}()
	if metadataValue(output.Metadata, "pfw-version") != s3MetadataVersion {
		return Entry{}, errors.Join(ErrInvalidEntry, errors.New("S3 object metadata version is missing or unsupported"))
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, metadataValue(output.Metadata, "pfw-expires-at"))
	if err != nil {
		return Entry{}, errors.Join(ErrInvalidEntry, fmt.Errorf("invalid S3 expires_at metadata: %w", err))
	}
	if !expiresAt.After(s.now()) {
		return Entry{}, ErrNotFound
	}
	if output.ContentLength == nil {
		return Entry{}, errors.Join(ErrInvalidEntry, errors.New("S3 object content length is missing"))
	}
	storedAt, err := time.Parse(time.RFC3339Nano, metadataValue(output.Metadata, "pfw-stored-at"))
	if err != nil {
		return Entry{}, errors.Join(ErrInvalidEntry, fmt.Errorf("invalid S3 stored_at metadata: %w", err))
	}
	headers, err := decodeS3Headers(metadataValue(output.Metadata, "pfw-headers"))
	if err != nil {
		return Entry{}, errors.Join(ErrInvalidEntry, err)
	}
	entry := Entry{
		Headers:   headers,
		Body:      output.Body,
		SHA256:    metadataValue(output.Metadata, "pfw-sha256"),
		Size:      *output.ContentLength,
		StoredAt:  storedAt,
		ExpiresAt: expiresAt,
	}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, err
	}
	closeOnError = false
	return entry, nil
}

func (s *S3Store) Put(ctx context.Context, key string, req PutRequest) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := ValidatePut(req); err != nil {
		return err
	}
	headers, err := encodeS3Headers(SafeHeaders(req.Headers))
	if err != nil {
		return err
	}
	input := &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s.objectKey(key)),
		Body:          req.Body,
		ContentLength: aws.Int64(req.Size),
		Metadata: map[string]string{
			"pfw-version":    s3MetadataVersion,
			"pfw-sha256":     req.SHA256,
			"pfw-stored-at":  req.StoredAt.UTC().Format(time.RFC3339Nano),
			"pfw-expires-at": req.ExpiresAt.UTC().Format(time.RFC3339Nano),
			"pfw-headers":    headers,
		},
	}
	if contentType := req.Headers.Get("Content-Type"); contentType != "" {
		input.ContentType = aws.String(contentType)
	}
	if s.expectedBucketOwner != "" {
		input.ExpectedBucketOwner = aws.String(s.expectedBucketOwner)
	}
	_, err = s.client.PutObject(ctx, input)
	return err
}

func (s *S3Store) objectKey(key string) string {
	name := path.Join("v1", key[:2], key+".artifact")
	if s.prefix == "" {
		return name
	}
	return s.prefix + "/" + name
}

func encodeS3Headers(headers http.Header) (string, error) {
	raw, err := json.Marshal(headers)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > maxS3HeaderMetadataSize {
		return "", fmt.Errorf("S3 cache header metadata is %d bytes; maximum is %d", len(encoded), maxS3HeaderMetadataSize)
	}
	return encoded, nil
}

func decodeS3Headers(value string) (http.Header, error) {
	if value == "" {
		return nil, errors.New("S3 cache header metadata is missing")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode S3 cache headers: %w", err)
	}
	var headers http.Header
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, fmt.Errorf("decode S3 cache headers: %w", err)
	}
	return SafeHeaders(headers), nil
}

func metadataValue(metadata map[string]string, key string) string {
	for candidate, value := range metadata {
		if strings.EqualFold(candidate, key) {
			return value
		}
	}
	return ""
}

func isS3NotFound(err error) bool {
	var noSuchKey *types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return true
	}
	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return false
	}
	switch apiError.ErrorCode() {
	case "NoSuchKey", "NotFound", "404":
		return true
	default:
		return false
	}
}
