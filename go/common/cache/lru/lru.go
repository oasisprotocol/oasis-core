// Package LRU implements an in-memory Least-Recently-Used cache.
package lru

import (
	"container/list"
	"errors"
	"sync"
)

// ErrTooLarge is the error returned when a value is too large for the cache.
var ErrTooLarge = errors.New("lru: value size exceeds maximum capacity")

// Sizable is the interface implemented by types that support returning their
// own memory size in bytes.
type Sizeable interface {
	// Size returns the size of the instance in bytes.
	Size() uint64
}

// OnEvictFunc is the function signature for the on-evict callback.
//
// Note: The callback does not support calling routines on it's associated
// cache instance.
type OnEvictFunc func(key, value interface{})

// Cache is an LRU cache instance.
type Cache struct {
	sync.Mutex

	lru     *list.List
	entries map[interface{}]*list.Element

	onEvict OnEvictFunc

	capacityInBytes bool
	capacity        uint64
	size            uint64
}

type cacheEntry struct {
	key   interface{}
	value interface{}
}

// Put inserts the key/value pair into the cache.  If the key is already present,
// the value is updated, and the entry is moved to the most-recently-used position.
func (c *Cache) Put(key, value interface{}) error {
	c.Lock()
	defer c.Unlock()

	if elem, ok := c.entries[key]; ok {
		// Key already present in cache.  Evict the existing entry, but do not
		// call the callback.
		c.lru.Remove(elem)
		delete(c.entries, key)
		c.size -= c.getValueSize(elem.Value.(*cacheEntry).value)
	}

	// Sanity check that the value will fit.
	// We do this after removing a possibly existing key to make sure we have
	// a consistent state in case the previous value was smaller, but the newer
	// one is too large to fit.
	valueSize := c.getValueSize(value)
	if c.capacity > 0 && c.capacityInBytes && valueSize > c.capacity {
		return ErrTooLarge
	}

	// Evict entries till there is enough capacity, be it slots or bytes.
	// The item is guaranteed to fit if enough entries are evicted.
	if c.capacity > 0 && valueSize > c.capacity-c.size {
		c.evictEntries(valueSize)
	}

	elem := c.lru.PushFront(&cacheEntry{
		key:   key,
		value: value,
	})
	c.entries[key] = elem
	c.size += valueSize

	return nil
}

// Get returns the value associated with the key and true if it is present in
// the cache, and the entry is moved to the most-recently-used position.
func (c *Cache) Get(key interface{}) (interface{}, bool) {
	return c.getEntry(key, false)
}

// Peek returns the value associated with the key and true if it is present in
// the cache, without altering the access time of the entry.
func (c *Cache) Peek(key interface{}) (interface{}, bool) {
	return c.getEntry(key, true)
}

// Remove removes the key from the cache and returns true if the key existed, otherwise false.
func (c *Cache) Remove(key interface{}) bool {
	c.Lock()
	defer c.Unlock()

	elem, ok := c.entries[key]
	if ok {
		c.lru.Remove(elem)
		delete(c.entries, key)
		c.size -= c.getValueSize(elem.Value.(*cacheEntry).value)
	}

	return ok
}

// Keys returns the keys for every entry in the cache, from the least-recently-used
// to the most-recently-used.
func (c *Cache) Keys() []interface{} {
	c.Lock()
	defer c.Unlock()

	vec := make([]interface{}, 0, c.lru.Len())
	for elem := c.lru.Back(); elem != nil; elem = elem.Prev() {
		vec = append(vec, elem.Value.(*cacheEntry).key)
	}
	return vec
}

// Clear empties the cache.
func (c *Cache) Clear() {
	c.Lock()
	defer c.Unlock()

	c.size = 0
	c.lru = list.New()
	c.entries = make(map[interface{}]*list.Element)
}

// Size returns the current cache size in the units specified by a `Capacity`
// option at creation time.
func (c *Cache) Size() uint64 {
	c.Lock()
	defer c.Unlock()

	return c.size
}

func (c *Cache) getEntry(key interface{}, isPeek bool) (interface{}, bool) {
	c.Lock()
	defer c.Unlock()

	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if !isPeek {
		c.lru.MoveToFront(elem)
	}
	return elem.Value.(*cacheEntry).value, true
}

func (c *Cache) evictEntries(targetCapacity uint64) {
	for c.lru.Len() > 0 && c.capacity-c.size < targetCapacity {
		elem := c.lru.Back()
		c.lru.Remove(elem)

		ent := elem.Value.(*cacheEntry)
		delete(c.entries, ent.key)
		c.size -= c.getValueSize(ent.value)

		if c.onEvict != nil {
			c.onEvict(ent.key, ent.value)
		}
	}
}

func (c *Cache) getValueSize(value interface{}) uint64 {
	if !c.capacityInBytes {
		// Capacity at initialization time was set to a number of
		// elements.
		return 1
	}

	return value.(Sizeable).Size()
}

// New creates a new LRU cache instance with the specified options.
func New(options ...Option) (*Cache, error) {
	c := &Cache{
		lru:     list.New(),
		entries: make(map[interface{}]*list.Element),
	}

	for _, v := range options {
		if err := v(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// Option is a configuration option used when instantiating a cache.
type Option func(c *Cache) error

// Capacity sets the capacity of the new cache.  If the capacity is set
// as `inBytes`, it is assumed that all values inserted will implement
// `Sizable`.
//
// If no capacity is specified, the cache will have an unlimited size.
func Capacity(capacity uint64, inBytes bool) Option {
	return func(c *Cache) error {
		c.capacityInBytes = inBytes
		c.capacity = capacity
		return nil
	}
}

// OnEvict sets the on-evict callback.
func OnEvict(fn OnEvictFunc) Option {
	return func(c *Cache) error {
		c.onEvict = fn
		return nil
	}
}
