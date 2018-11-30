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
		c.metaAdd(key, r)
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

func (c *Cache) Set(key api.Key, value []byte) {
	c.Lock()
	defer c.Unlock()

	r := c.keys[key]

	if r == nil {
		// No cache entry found, add it.
		c.db.SetSync(key[:], value)
		r = &ring.Ring{Value: &entry{ref: false, ptype: ptCold, key: key}}
		c.metaAdd(key, r)
		c.countCold++
		return
	}

	mentry := r.Value.(*entry)

	val := c.db.Get(key[:])

	if val == nil {
		// Cache entry was a hot or cold page.
		c.db.SetSync(key[:], value)
		mentry.ref = true
		return
	}

	// Cache entry was a test page.
	if c.memCold < c.memMax {
		c.memCold++
	}
	mentry.ref = false
	c.db.SetSync(key[:], value)
	mentry.ptype = ptHot
	c.countTest--
	c.metaDel(r)
	c.metaAdd(key, r)
	c.countHot++
}

func (c *Cache) metaAdd(key api.Key, r *ring.Ring) {
	c.evict()

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

func (c *Cache) metaDel(r *ring.Ring) {
	c.db.DeleteSync(r.Value.(*entry).key[:])
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

func (c *Cache) evict() {
	for c.memMax <= c.countHot+c.countCold {
		c.runHandCold()
	}
}

func (c *Cache) runHandCold() {
	mentry := c.handCold.Value.(*entry)

	if mentry.ptype == ptCold {

		if mentry.ref {
			mentry.ptype = ptHot
			mentry.ref = false
			c.countCold--
			c.countHot++
		} else {
			mentry.ptype = ptTest
			c.db.DeleteSync(mentry.key[:])
			c.countCold--
			c.countTest++
			for c.memMax < c.countTest {
				c.runHandTest()
			}
		}
	}

	c.handCold = c.handCold.Next()

	for c.memMax-c.memCold < c.countHot {
		c.runHandHot()
	}
}

func (c *Cache) runHandHot() {
	if c.handHot == c.handTest {
		c.runHandTest()
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

func (c *Cache) runHandTest() {
	if c.handTest == c.handCold {
		c.runHandCold()
	}

	mentry := c.handTest.Value.(*entry)

	if mentry.ptype == ptTest {

		prev := c.handTest.Prev()
		c.metaDel(c.handTest)
		c.handTest = prev

		c.countTest--
		if c.memCold > 1 {
			c.memCold--
		}
	}

	c.handTest = c.handTest.Next()
}
