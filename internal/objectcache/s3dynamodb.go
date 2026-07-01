package objectcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3DynamoDBStore struct {
	s3Client  *s3.Client
	ddbClient *dynamodb.Client
	bucket    string
	prefix    string
	table     string
	now       func() time.Time
}

type S3DynamoDBConfig struct {
	S3Client  *s3.Client
	DDBClient *dynamodb.Client
	Bucket    string
	Prefix    string
	Table     string
}

func NewS3DynamoDBStore(cfg S3DynamoDBConfig) *S3DynamoDBStore {
	return &S3DynamoDBStore{
		s3Client:  cfg.S3Client,
		ddbClient: cfg.DDBClient,
		bucket:    cfg.Bucket,
		prefix:    strings.Trim(cfg.Prefix, "/"),
		table:     cfg.Table,
		now:       time.Now,
	}
}

func (s *S3DynamoDBStore) Get(ctx context.Context, key string) (Entry, bool, error) {
	out, err := s.ddbClient.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.table),
		Key: map[string]types.AttributeValue{
			"cache_key": &types.AttributeValueMemberS{Value: key},
		},
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return Entry{}, false, err
	}
	if len(out.Item) == 0 {
		return Entry{}, false, nil
	}
	var record ddbRecord
	if err := attributevalue.UnmarshalMap(out.Item, &record); err != nil {
		return Entry{}, false, err
	}
	body, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(record.S3Key),
	})
	if err != nil {
		return Entry{}, false, err
	}
	return record.entry(body.Body), true, nil
}

func (s *S3DynamoDBStore) Put(ctx context.Context, req PutRequest) error {
	now := s.now().UTC()
	body := req.Body
	shaHex := req.ComputedSHA256
	hasher := sha256.New()
	if shaHex == "" {
		body = io.TeeReader(req.Body, hasher)
	}
	s3Key := s.objectKey(req.Key)
	metadata := map[string]string{}
	if shaHex != "" {
		metadata["sha256"] = shaHex
	}
	if _, err := s.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(s3Key),
		Body:          body,
		ContentLength: aws.Int64(req.ContentLength),
		ContentType:   aws.String(req.Headers.Get("Content-Type")),
		Metadata:      metadata,
	}); err != nil {
		return err
	}
	if shaHex == "" {
		shaHex = hex.EncodeToString(hasher.Sum(nil))
	}
	metadata["sha256"] = shaHex
	headersJSON, err := json.Marshal(SafeHeaders(req.Headers))
	if err != nil {
		return err
	}
	record := ddbRecord{
		CacheKey:          req.Key,
		S3Key:             s3Key,
		StatusCode:        req.StatusCode,
		HeadersJSON:       string(headersJSON),
		SHA256:            shaHex,
		Size:              req.ContentLength,
		FetchedAt:         now.Format(time.RFC3339),
		ExpiresAt:         now.Add(req.TTL).Format(time.RFC3339),
		StaleIfErrorUntil: now.Add(req.TTL + req.StaleIfError).Format(time.RFC3339),
		Immutable:         req.Immutable,
	}
	item, err := attributevalue.MarshalMap(record)
	if err != nil {
		return err
	}
	_, err = s.ddbClient.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      item,
	})
	return err
}

func (s *S3DynamoDBStore) objectKey(key string) string {
	name := key + ".body"
	if s.prefix == "" {
		return name
	}
	return path.Join(s.prefix, name)
}

type ddbRecord struct {
	CacheKey          string `dynamodbav:"cache_key"`
	S3Key             string `dynamodbav:"s3_key"`
	StatusCode        int    `dynamodbav:"status_code"`
	HeadersJSON       string `dynamodbav:"headers_json"`
	SHA256            string `dynamodbav:"sha256"`
	Size              int64  `dynamodbav:"size"`
	FetchedAt         string `dynamodbav:"fetched_at"`
	ExpiresAt         string `dynamodbav:"expires_at"`
	StaleIfErrorUntil string `dynamodbav:"stale_if_error_until"`
	Immutable         bool   `dynamodbav:"immutable"`
}

func (r ddbRecord) entry(body io.ReadCloser) Entry {
	headers := http.Header{}
	_ = json.Unmarshal([]byte(r.HeadersJSON), &headers)
	return Entry{
		Key:               r.CacheKey,
		StatusCode:        r.StatusCode,
		Headers:           headers,
		Body:              body,
		SHA256:            r.SHA256,
		Size:              r.Size,
		FetchedAt:         parseTime(r.FetchedAt),
		ExpiresAt:         parseTime(r.ExpiresAt),
		StaleIfErrorUntil: parseTime(r.StaleIfErrorUntil),
		Immutable:         r.Immutable,
	}
}

func parseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed
}
