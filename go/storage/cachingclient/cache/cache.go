// LevelDB-backed CLOCK-Pro cache
//
// Based on the MIT-licensed code at:
//     https://github.com/dgryski/go-clockpro/blob/master/clockpro.go

package cache

import (
	"container/ring"
	"path/filepath"
	"sync"

	tenderdb "github.com/tendermint/tendermint/libs/db"

	"github.com/oasislabs/ekiden/go/storage/api"
)

type pageType int

const (
	ptTest pageType = iota
	ptCold
	ptHot
)

type entry struct {
	ptype pageType
	key   api.Key
	ref   bool
}

// KeyValue is a (key, value) tuple.
type KeyValue struct {
	Key   api.Key
	Value []byte
}

// Cache is a LevelDB-backed CLOCK-Pro cache.
type Cache struct {
	sync.Mutex

	db tenderdb.DB

	memMax  int
	memCold int
	keys    map[api.Key]*ring.Ring

	handHot  *ring.Ring
	handCold *ring.Ring
	handTest *ring.Ring

	countHot  int
	countCold int
	countTest int
}

func New(path string, size int) (*Cache, error) {
	dir, file := filepath.Split(path)
	db := tenderdb.NewDB(file, tenderdb.LevelDBBackend, dir)

	c := &Cache{
		db:      db,
		memMax:  size,
		memCold: size,
		keys:    make(map[api.Key]*ring.Ring),
	}

	// Populate keys from database.
	iter := db.Iterator(nil, nil)
	defer iter.Close()

	for ; iter.Valid(); iter.Next() {
		// Start with fresh metadata.
		var key api.Key
		copy(key[:], iter.Key()[:])

		r := &ring.Ring{Value: &entry{ref: false, ptype: ptCold, key: key}}

		c.keys[key] = r
		batch := c.db.NewBatch()
		c.metaAdd(key, r, batch)
		batch.Write()
		c.countCold++
	}

	return c, nil
}

func (c *Cache) Cleanup() {
	c.db.Close()
}

func (c *Cache) Get(key api.Key) []byte {
	c.Lock()
	defer c.Unlock()

	r := c.keys[key]

	if r == nil {
		return nil
	}

	mentry := r.Value.(*entry)

	val := c.db.Get(key[:])

	if val != nil {
		mentry.ref = true
		return val
	}

	return nil
}

func (c *Cache) SetBatch(values []KeyValue) {
	c.Lock()
	defer c.Unlock()

	batch := c.db.NewBatch()

	for _, item := range values {
		key := item.Key
		value := item.Value

		r := c.keys[key]

		if r == nil {
			// No cache entry found, add it.
			batch.Set(key[:], value)
			r = &ring.Ring{Value: &entry{ref: false, ptype: ptCold, key: key}}
			c.metaAdd(key, r, batch)
			c.countCold++
			continue
		}

		mentry := r.Value.(*entry)

		val := c.db.Get(key[:])

		if val == nil {
			// Cache entry was a hot or cold page.
			batch.Set(key[:], value)
			mentry.ref = true
			continue
		}

		// Cache entry was a test page.
		if c.memCold < c.memMax {
			c.memCold++
		}
		mentry.ref = false
		batch.Set(key[:], value)
		mentry.ptype = ptHot
		c.countTest--
		c.metaDel(r, batch)
		c.metaAdd(key, r, batch)
		c.countHot++
	}

	batch.Write()
}

func (c *Cache) Set(key api.Key, value []byte) {
	c.SetBatch([]KeyValue{KeyValue{key, value}})
}

func (c *Cache) metaAdd(key api.Key, r *ring.Ring, batch tenderdb.Batch) {
	c.evict(batch)

	c.keys[key] = r
	r.Link(c.handHot)

	if c.handHot == nil {
		// Handle first element.
		c.handHot = r
		c.handCold = r
		c.handTest = r
	}

	if c.handCold == c.handHot {
		c.handCold = c.handCold.Prev()
	}
}

func (c *Cache) metaDel(r *ring.Ring, batch tenderdb.Batch) {
	batch.Delete(r.Value.(*entry).key[:])
	delete(c.keys, r.Value.(*entry).key)

	if r == c.handHot {
		c.handHot = c.handHot.Prev()
	}

	if r == c.handCold {
		c.handCold = c.handCold.Prev()
	}

	if r == c.handTest {
		c.handTest = c.handTest.Prev()
	}

	r.Prev().Unlink(1)
}

func (c *Cache) evict(batch tenderdb.Batch) {
	for c.memMax <= c.countHot+c.countCold {
		c.runHandCold(batch)
	}
}

func (c *Cache) runHandCold(batch tenderdb.Batch) {
	mentry := c.handCold.Value.(*entry)

	if mentry.ptype == ptCold {

		if mentry.ref {
			mentry.ptype = ptHot
			mentry.ref = false
			c.countCold--
			c.countHot++
		} else {
			mentry.ptype = ptTest
			batch.Delete(mentry.key[:])
			c.countCold--
			c.countTest++
			for c.memMax < c.countTest {
				c.runHandTest(batch)
			}
		}
	}

	c.handCold = c.handCold.Next()

	for c.memMax-c.memCold < c.countHot {
		c.runHandHot(batch)
	}
}

func (c *Cache) runHandHot(batch tenderdb.Batch) {
	if c.handHot == c.handTest {
		c.runHandTest(batch)
	}

	mentry := c.handHot.Value.(*entry)

	if mentry.ptype == ptHot {

		if mentry.ref {
			mentry.ref = false
		} else {
			mentry.ptype = ptCold
			c.countHot--
			c.countCold++
		}
	}

	c.handHot = c.handHot.Next()
}

func (c *Cache) runHandTest(batch tenderdb.Batch) {
	if c.handTest == c.handCold {
		c.runHandCold(batch)
	}

	mentry := c.handTest.Value.(*entry)

	if mentry.ptype == ptTest {

		prev := c.handTest.Prev()
		c.metaDel(c.handTest, batch)
		c.handTest = prev

		c.countTest--
		if c.memCold > 1 {
			c.memCold--
		}
	}

	c.handTest = c.handTest.Next()
}
