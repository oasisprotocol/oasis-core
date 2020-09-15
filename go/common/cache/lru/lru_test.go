package lru

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLRUCapacityEntries(t *testing.T) {
	require := require.New(t)

	const cacheSize = 5

	var (
		nrEvictCallbacks         int
		evictedKey, evictedValue interface{}
	)

	cache, err := New(
		Capacity(uint64(cacheSize), false),
		OnEvict(func(k, v interface{}) {
			evictedKey, evictedValue = k, v
			nrEvictCallbacks++
		}),
	)
	require.NoError(err, "New")

	entries := makeEntries(cacheSize)
	for _, ent := range entries {
		err = cache.Put(ent.key, ent)
		require.NoError(err, "Put")
	}

	for _, ent := range entries {
		rawEnt, ok := cache.Peek(ent.key)
		require.True(ok, "Peek - present")
		require.Equal(ent, rawEnt, "Peek - entry")
	}

	keys := cache.Keys()
	for i, ent := range entries {
		rawEnt, ok := cache.Get(ent.key)
		require.True(ok, "Get - present")
		require.Equal(ent, rawEnt, "Get - entry")
		require.Equal(keys[i], ent.key, "Keys - key")
	}

	// Access the entries in random order.
	order := rand.New(rand.NewSource(23)).Perm(len(entries))
	for _, v := range order {
		rawEnt, ok := cache.Get(entries[v].key)
		require.True(ok, "Get - random order")
		require.Equal(entries[v], rawEnt, "Get - random order")
	}

	// Insert an entry to force eviction.
	order = append(order, len(entries))
	evictEnt := makeEntry("evictionTest")
	entries = append(entries, evictEnt)

	err = cache.Put(evictEnt.key, evictEnt)
	require.NoError(err, "Put - will evict")
	require.Equal(1, nrEvictCallbacks, "Put - OnEvict called")
	require.Equal(entries[order[0]].key, evictedKey, "Evict - key")
	require.Equal(entries[order[0]], evictedValue, "Evict - value")

	for i, k := range cache.Keys() {
		entIdx := order[i+1]
		require.Equal(entries[entIdx].key, k)
	}

	// Update a entry.
	updateVal := "Yes I know this mixes value types."
	err = cache.Put(entries[order[1]].key, updateVal)
	require.NoError(err, "Put - update")
	v, ok := cache.Get(entries[order[1]].key)
	require.True(ok, "Get - update")
	require.Equal(updateVal, v, "Get - update")

	require.Equal(uint64(cacheSize), cache.Size(), "Size")

	// Clear cache.
	cache.Clear()
	_, ok = cache.Peek(entries[0].key)
	require.False(ok, "Peek - expected entry to not exist after removal")
	require.Empty(cache.Keys(), "Empty keys")
	require.EqualValues(0, cache.Size(), "Empty size")
}

func TestLRUCapacityBytes(t *testing.T) {
	require := require.New(t)

	const cacheSize = 5

	cache, err := New(
		Capacity(uint64(cacheSize*sha256.Size), true),
	)
	require.NoError(err, "New")

	entries := makeEntries(cacheSize)
	for _, ent := range entries {
		err = cache.Put(ent.key, ent)
		require.NoError(err, "Put")
	}

	hugeEnt := &testEntry{
		key:   "huge entry - should fail",
		value: make([]byte, 1024768),
	}
	err = cache.Put(hugeEnt.key, hugeEnt)
	require.Error(err, "Put - huge entry")

	newEnt := makeEntry("new entry")
	err = cache.Put(newEnt.key, newEnt)
	require.NoError(err, "Put - evict")

	_, ok := cache.Peek(entries[0].key)
	require.False(ok, "Put - expected entry evicted")
}

func TestLRURemoval(t *testing.T) {
	require := require.New(t)

	const cacheSize = 5

	cache, err := New(
		Capacity(uint64(cacheSize*sha256.Size), true),
	)
	require.NoError(err, "New")

	entries := makeEntries(cacheSize)
	for _, ent := range entries {
		err = cache.Put(ent.key, ent)
		require.NoError(err, "Put")
	}

	sizeBeforeRemoval := cache.Size()

	existed := cache.Remove(entries[0].key)
	require.True(existed, "Remove - expected entry to exist")

	sizeAfterRemoval := cache.Size()

	_, ok := cache.Peek(entries[0].key)
	require.False(ok, "Peek - expected entry to not exist after removal")
	require.Equal(sizeBeforeRemoval-entries[0].Size(), sizeAfterRemoval, "Size - expected size to reduce by entry size after removal")
}

type testEntry struct {
	key   string
	value []byte
}

func (e *testEntry) Size() uint64 {
	return uint64(len(e.value))
}

func makeEntries(nr int) []*testEntry {
	vec := make([]*testEntry, 0, nr)
	for i := 0; i < nr; i++ {
		vec = append(vec, makeEntry(fmt.Sprintf("key-%d", i)))
	}

	return vec
}

func makeEntry(k string) *testEntry {
	v := sha256.Sum256([]byte(k))
	return &testEntry{
		key:   k,
		value: v[:],
	}
}
