package cache

import (
	"sync"
	"time"
)

type Cache[T any] struct {
	mu    sync.Mutex
	items map[string]entry[T]
}

type entry[T any] struct {
	value     T
	expiresAt time.Time
}

func New[T any]() *Cache[T] {
	return &Cache[T]{items: map[string]entry[T]{}}
}

func (c *Cache[T]) Get(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.items[key]
	var zero T
	if !ok {
		return zero, false
	}
	if !item.expiresAt.IsZero() && time.Now().After(item.expiresAt) {
		delete(c.items, key)
		return zero, false
	}
	return item.value, true
}

func (c *Cache[T]) Set(key string, value T, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item := entry[T]{value: value}
	if ttl > 0 {
		item.expiresAt = time.Now().Add(ttl)
	}
	c.items[key] = item
}

func (c *Cache[T]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = map[string]entry[T]{}
}
