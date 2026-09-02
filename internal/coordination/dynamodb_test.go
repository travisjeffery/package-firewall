package coordination

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestDynamoDBLeaseLifecycleUsesConditionalOwnership(t *testing.T) {
	client := &fakeDynamoDB{}
	coordinator, err := NewDynamoDB(DynamoDBConfig{Client: client, Table: "coordination", KeyPrefix: "test"})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.now = func() time.Time { return time.Unix(1_000, 0) }
	coordinator.owner = func() (string, error) { return "owner-1", nil }

	lease, acquired, err := coordinator.TryAcquire(context.Background(), "artifact:key", 30*time.Second)
	if err != nil || !acquired || lease == nil {
		t.Fatalf("acquired = %v lease = %v error = %v", acquired, lease, err)
	}
	acquire := client.updates[0]
	if aws.ToString(acquire.TableName) != "coordination" || aws.ToString(acquire.ConditionExpression) != "attribute_not_exists(#owner) OR #expires_at <= :now" {
		t.Fatalf("acquire input = %#v", acquire)
	}
	assertNumber(t, acquire.ExpressionAttributeValues[":now"], "1000")
	assertNumber(t, acquire.ExpressionAttributeValues[":expires_at"], "1030")
	assertString(t, acquire.ExpressionAttributeValues[":owner"], "owner-1")
	key := assertString(t, acquire.Key[keyAttribute], "")
	if key == "" {
		t.Fatal("coordination key is empty")
	}

	coordinator.now = func() time.Time { return time.Unix(1_010, 0) }
	if err := lease.Renew(context.Background(), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	renew := client.updates[1]
	if got := assertString(t, renew.Key[keyAttribute], ""); got != key {
		t.Fatalf("renew key = %q want %q", got, key)
	}
	if aws.ToString(renew.ConditionExpression) != "#owner = :owner AND #expires_at >= :now" {
		t.Fatalf("renew condition = %q", aws.ToString(renew.ConditionExpression))
	}
	assertNumber(t, renew.ExpressionAttributeValues[":expires_at"], "1040")

	if err := lease.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	release := client.deletes[0]
	if got := assertString(t, release.Key[keyAttribute], ""); got != key {
		t.Fatalf("release key = %q want %q", got, key)
	}
	if aws.ToString(release.ConditionExpression) != "#owner = :owner" {
		t.Fatalf("release condition = %q", aws.ToString(release.ConditionExpression))
	}
}

func TestDynamoDBLeaseReportsContentionAndLostOwnership(t *testing.T) {
	conditional := &types.ConditionalCheckFailedException{}
	client := &fakeDynamoDB{updateErrors: []error{conditional, nil, conditional}, deleteErrors: []error{conditional}}
	coordinator, err := NewDynamoDB(DynamoDBConfig{Client: client, Table: "coordination"})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.owner = func() (string, error) { return "owner", nil }

	lease, acquired, err := coordinator.TryAcquire(context.Background(), "busy", time.Minute)
	if err != nil || acquired || lease != nil {
		t.Fatalf("busy acquire = (%v, %v, %v)", lease, acquired, err)
	}
	lease, acquired, err = coordinator.TryAcquire(context.Background(), "free", time.Minute)
	if err != nil || !acquired {
		t.Fatalf("free acquire = (%v, %v, %v)", lease, acquired, err)
	}
	if err := lease.Renew(context.Background(), time.Minute); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("renew error = %v", err)
	}
	if err := lease.Release(context.Background()); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("release error = %v", err)
	}
}

func TestDynamoDBCooldownKeepsLatestExpiry(t *testing.T) {
	client := &fakeDynamoDB{
		getOutputs: []*dynamodb.GetItemOutput{{Item: map[string]types.AttributeValue{
			expiresAtAttribute: &types.AttributeValueMemberN{Value: "1060"},
		}}},
		updateErrors: []error{&types.ConditionalCheckFailedException{}},
	}
	coordinator, err := NewDynamoDB(DynamoDBConfig{Client: client, Table: "coordination"})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.now = func() time.Time { return time.Unix(1_000, 0) }

	until, err := coordinator.Cooldown(context.Background(), "maven")
	if err != nil || !until.Equal(time.Unix(1_060, 0)) {
		t.Fatalf("cooldown = %s error = %v", until, err)
	}
	if !aws.ToBool(client.gets[0].ConsistentRead) {
		t.Fatal("cooldown read is not strongly consistent")
	}
	if err := coordinator.SetCooldown(context.Background(), "maven", time.Unix(1_030, 0)); err != nil {
		t.Fatal(err)
	}
	update := client.updates[0]
	if aws.ToString(update.ConditionExpression) != "attribute_not_exists(#expires_at) OR #expires_at < :expires_at" {
		t.Fatalf("cooldown condition = %q", aws.ToString(update.ConditionExpression))
	}
	assertNumber(t, update.ExpressionAttributeValues[":expires_at"], "1030")
}

type fakeDynamoDB struct {
	gets         []*dynamodb.GetItemInput
	updates      []*dynamodb.UpdateItemInput
	deletes      []*dynamodb.DeleteItemInput
	getOutputs   []*dynamodb.GetItemOutput
	getErrors    []error
	updateErrors []error
	deleteErrors []error
}

func (f *fakeDynamoDB) GetItem(_ context.Context, input *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	f.gets = append(f.gets, input)
	index := len(f.gets) - 1
	if index < len(f.getErrors) && f.getErrors[index] != nil {
		return nil, f.getErrors[index]
	}
	if index < len(f.getOutputs) && f.getOutputs[index] != nil {
		return f.getOutputs[index], nil
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (f *fakeDynamoDB) UpdateItem(_ context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.updates = append(f.updates, input)
	index := len(f.updates) - 1
	if index < len(f.updateErrors) && f.updateErrors[index] != nil {
		return nil, f.updateErrors[index]
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func (f *fakeDynamoDB) DeleteItem(_ context.Context, input *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	f.deletes = append(f.deletes, input)
	index := len(f.deletes) - 1
	if index < len(f.deleteErrors) && f.deleteErrors[index] != nil {
		return nil, f.deleteErrors[index]
	}
	return &dynamodb.DeleteItemOutput{}, nil
}

func assertString(t *testing.T, value types.AttributeValue, want string) string {
	t.Helper()
	actual, ok := value.(*types.AttributeValueMemberS)
	if !ok {
		t.Fatalf("attribute = %#v, want string", value)
	}
	if want != "" && actual.Value != want {
		t.Fatalf("attribute = %q want %q", actual.Value, want)
	}
	return actual.Value
}

func assertNumber(t *testing.T, value types.AttributeValue, want string) {
	t.Helper()
	actual, ok := value.(*types.AttributeValueMemberN)
	if !ok || actual.Value != want {
		t.Fatalf("attribute = %#v want number %q", value, want)
	}
}
