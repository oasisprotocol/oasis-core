package tdx

import (
	"fmt"
	"math"
	"sync"
)

// CidPool is a pool of context IDs (CIDs) that can be assigned to virtual machines (VMs) to
// identify them in VSOCK connections.
type CidPool struct {
	l sync.Mutex

	start uint32
	end   uint32

	free map[uint32]struct{}
	used map[uint32]struct{}
}

// NewCidPool creates a new CID pool containing the given range of CIDs.
func NewCidPool(start, count uint32) (*CidPool, error) {
	if start < 10 {
		return nil, fmt.Errorf("CID identifiers between 0 and 10 are reserved")
	}
	if count > 4096 {
		return nil, fmt.Errorf("maximum CID pool size is 4096")
	}
	if start > math.MaxUint32-count {
		return nil, fmt.Errorf("CID pool would overflow")
	}

	c := CidPool{
		start: start,
		end:   start + count,
		free:  make(map[uint32]struct{}),
		used:  make(map[uint32]struct{}),
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

// AllocateExact allocates a specific CID from the pool.
func (c *CidPool) AllocateExact(cid uint32) error {
	c.l.Lock()
	defer c.l.Unlock()

	if cid < c.start || cid >= c.end {
		return fmt.Errorf("CID %d is outside the allocated range (%d - %d)", cid, c.start, c.end)
	}
	if _, ok := c.free[cid]; !ok {
		return fmt.Errorf("CID %d is already in use", cid)
	}

	c.used[cid] = struct{}{}
	delete(c.free, cid)
	return nil
}

// Release releases the given previously allocated CID back to the pool.
func (c *CidPool) Release(cid uint32) bool {
	c.l.Lock()
	defer c.l.Unlock()

	if _, ok := c.used[cid]; !ok {
		return false
	}
	delete(c.used, cid)
	c.free[cid] = struct{}{}
	return true
}
