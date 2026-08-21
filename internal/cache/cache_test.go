package cache

import (
	"testing"
	"time"
)

func TestCacheMaxEntriesEvictsOldestKeys(t *testing.T) {
	c := NewWithMaxEntries[int](2)
	c.Set("first", 1, 0)
	c.Set("second", 2, 0)
	c.Set("third", 3, 0)

	if _, ok := c.Get("first"); ok {
		t.Fatal("expected oldest key to be evicted")
	}
	if got, ok := c.Get("second"); !ok || got != 2 {
		t.Fatalf("second = %d, %v; want 2, true", got, ok)
	}
	if got, ok := c.Get("third"); !ok || got != 3 {
		t.Fatalf("third = %d, %v; want 3, true", got, ok)
	}
}

func TestCacheMaxEntriesDoesNotDuplicateUpdatedKeys(t *testing.T) {
	c := NewWithMaxEntries[int](2)
	c.Set("first", 1, 0)
	c.Set("first", 10, 0)
	c.Set("second", 2, 0)

	if got, ok := c.Get("first"); !ok || got != 10 {
		t.Fatalf("first = %d, %v; want 10, true", got, ok)
	}

	c.Set("third", 3, 0)
	if _, ok := c.Get("first"); ok {
		t.Fatal("expected updated oldest key to be evicted once")
	}
	if _, ok := c.Get("second"); !ok {
		t.Fatal("expected second key to remain")
	}
}

func TestCachePurgeClearsEvictionOrder(t *testing.T) {
	c := NewWithMaxEntries[int](1)
	c.Set("first", 1, 0)
	c.Purge()
	c.Set("second", 2, 0)

	if _, ok := c.Get("first"); ok {
		t.Fatal("expected purged key to be absent")
	}
	if got, ok := c.Get("second"); !ok || got != 2 {
		t.Fatalf("second = %d, %v; want 2, true", got, ok)
	}
}

func TestCacheExpiredEntriesDoNotPreventBoundedInsert(t *testing.T) {
	c := NewWithMaxEntries[int](1)
	c.Set("expired", 1, time.Nanosecond)
	time.Sleep(time.Millisecond)
	if _, ok := c.Get("expired"); ok {
		t.Fatal("expected expired key to be absent")
	}

	c.Set("fresh", 2, 0)
	if got, ok := c.Get("fresh"); !ok || got != 2 {
		t.Fatalf("fresh = %d, %v; want 2, true", got, ok)
	}
}

func TestCacheExpiredEntriesDoNotGrowEvictionOrder(t *testing.T) {
	c := NewWithMaxEntries[int](1)
	for i := 0; i < 3; i++ {
		c.Set("same", i, time.Nanosecond)
		time.Sleep(time.Millisecond)
		if _, ok := c.Get("same"); ok {
			t.Fatal("expected expired key to be absent")
		}
	}

	c.Set("same", 10, 0)
	if len(c.order) != 1 {
		t.Fatalf("order length = %d, want 1", len(c.order))
	}
	if got, ok := c.Get("same"); !ok || got != 10 {
		t.Fatalf("same = %d, %v; want 10, true", got, ok)
	}
}
