package tdx

import (
	"fmt"
	"sync"
)

// CidPool is a pool of CIDs that can be assigned to VMs.
type CidPool struct {
	l sync.Mutex

	free map[uint32]struct{}
	used map[uint32]struct{}
}

// NewCidPool creates a new CID pool containing the given range of CIDs.
func NewCidPool(start, count uint32) (*CidPool, error) {
	if start < 10 {
		return nil, fmt.Errorf("CID identifiers between 0 and 10 are reserved")
	}

	c := CidPool{
		free: make(map[uint32]struct{}),
		used: make(map[uint32]struct{}),
	}
	for cid := start; cid < start+count; cid++ {
		c.free[cid] = struct{}{}
	}
	return &c, nil
}

// Allocate allocates a CID from the pool.
func (c *CidPool) Allocate() (uint32, error) {
	c.l.Lock()
	defer c.l.Unlock()

	for cid := range c.free {
		c.used[cid] = struct{}{}
		delete(c.free, cid)
		return cid, nil
	}
	return 0, fmt.Errorf("no free CIDs available")
}

// Release releases the given previously allocated CID back to the pool.
func (c *CidPool) Release(cid uint32) {
	c.l.Lock()
	defer c.l.Unlock()

	if _, ok := c.used[cid]; !ok {
		return
	}
	delete(c.used, cid)
	c.free[cid] = struct{}{}
}
