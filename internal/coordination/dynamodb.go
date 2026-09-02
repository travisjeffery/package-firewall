package coordination

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	keyAttribute       = "coordination_key"
	ownerAttribute     = "owner"
	expiresAtAttribute = "expires_at"
)

type DynamoDBAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
}

type DynamoDBConfig struct {
	Client    DynamoDBAPI
	Table     string
	KeyPrefix string
}

type DynamoDBCoordinator struct {
	client    DynamoDBAPI
	table     string
	keyPrefix string
	now       func() time.Time
	owner     func() (string, error)
}

func NewDynamoDB(cfg DynamoDBConfig) (*DynamoDBCoordinator, error) {
	if cfg.Client == nil {
		return nil, errors.New("DynamoDB coordination client is required")
	}
	if strings.TrimSpace(cfg.Table) == "" {
		return nil, errors.New("DynamoDB coordination table is required")
	}
	prefix := strings.Trim(strings.TrimSpace(cfg.KeyPrefix), "#")
	if prefix == "" {
		prefix = "package-firewall"
	}
	return &DynamoDBCoordinator{
		client:    cfg.Client,
		table:     cfg.Table,
		keyPrefix: prefix,
		now:       time.Now,
		owner:     randomOwner,
	}, nil
}

func (c *DynamoDBCoordinator) TryAcquire(ctx context.Context, resource string, duration time.Duration) (Lease, bool, error) {
	owner, err := c.owner()
	if err != nil {
		return nil, false, fmt.Errorf("create coordination lease owner: %w", err)
	}
	now := c.now()
	key := c.itemKey("lease", resource)
	_, err = c.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key:       itemKey(key),
		ExpressionAttributeNames: map[string]string{
			"#expires_at": expiresAtAttribute,
			"#owner":      ownerAttribute,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":expires_at": number(now.Add(duration).Unix()),
			":now":        number(now.Unix()),
			":owner":      &types.AttributeValueMemberS{Value: owner},
		},
		ConditionExpression: aws.String("attribute_not_exists(#owner) OR #expires_at <= :now"),
		UpdateExpression:    aws.String("SET #owner = :owner, #expires_at = :expires_at"),
	})
	if isConditionalFailure(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("acquire DynamoDB coordination lease: %w", err)
	}
	return &dynamoLease{coordinator: c, key: key, owner: owner}, true, nil
}

func (c *DynamoDBCoordinator) Cooldown(ctx context.Context, route string) (time.Time, error) {
	output, err := c.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:            aws.String(c.table),
		Key:                  itemKey(c.itemKey("cooldown", route)),
		ConsistentRead:       aws.Bool(true),
		ProjectionExpression: aws.String("#expires_at"),
		ExpressionAttributeNames: map[string]string{
			"#expires_at": expiresAtAttribute,
		},
	})
	if err != nil {
		return time.Time{}, fmt.Errorf("read DynamoDB upstream cooldown: %w", err)
	}
	value, ok := output.Item[expiresAtAttribute].(*types.AttributeValueMemberN)
	if !ok {
		return time.Time{}, nil
	}
	seconds, err := strconv.ParseInt(value.Value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse DynamoDB upstream cooldown: %w", err)
	}
	until := time.Unix(seconds, 0)
	if !until.After(c.now()) {
		return time.Time{}, nil
	}
	return until, nil
}

func (c *DynamoDBCoordinator) SetCooldown(ctx context.Context, route string, until time.Time) error {
	_, err := c.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(c.table),
		Key:       itemKey(c.itemKey("cooldown", route)),
		ExpressionAttributeNames: map[string]string{
			"#expires_at": expiresAtAttribute,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":expires_at": number(until.Unix()),
		},
		ConditionExpression: aws.String("attribute_not_exists(#expires_at) OR #expires_at < :expires_at"),
		UpdateExpression:    aws.String("SET #expires_at = :expires_at"),
	})
	if isConditionalFailure(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("set DynamoDB upstream cooldown: %w", err)
	}
	return nil
}

func (c *DynamoDBCoordinator) itemKey(kind, resource string) string {
	digest := sha256.Sum256([]byte(resource))
	return c.keyPrefix + "#" + kind + "#" + hex.EncodeToString(digest[:])
}

type dynamoLease struct {
	coordinator *DynamoDBCoordinator
	key         string
	owner       string
}

func (l *dynamoLease) Renew(ctx context.Context, duration time.Duration) error {
	now := l.coordinator.now()
	_, err := l.coordinator.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(l.coordinator.table),
		Key:       itemKey(l.key),
		ExpressionAttributeNames: map[string]string{
			"#expires_at": expiresAtAttribute,
			"#owner":      ownerAttribute,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":expires_at": number(now.Add(duration).Unix()),
			":now":        number(now.Unix()),
			":owner":      &types.AttributeValueMemberS{Value: l.owner},
		},
		ConditionExpression: aws.String("#owner = :owner AND #expires_at >= :now"),
		UpdateExpression:    aws.String("SET #expires_at = :expires_at"),
	})
	if isConditionalFailure(err) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("renew DynamoDB coordination lease: %w", err)
	}
	return nil
}

func (l *dynamoLease) Release(ctx context.Context) error {
	_, err := l.coordinator.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(l.coordinator.table),
		Key:       itemKey(l.key),
		ExpressionAttributeNames: map[string]string{
			"#owner": ownerAttribute,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner": &types.AttributeValueMemberS{Value: l.owner},
		},
		ConditionExpression: aws.String("#owner = :owner"),
	})
	if isConditionalFailure(err) {
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("release DynamoDB coordination lease: %w", err)
	}
	return nil
}

func itemKey(value string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		keyAttribute: &types.AttributeValueMemberS{Value: value},
	}
}

func number(value int64) types.AttributeValue {
	return &types.AttributeValueMemberN{Value: strconv.FormatInt(value, 10)}
}

func randomOwner() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func isConditionalFailure(err error) bool {
	var failure *types.ConditionalCheckFailedException
	return errors.As(err, &failure)
}
