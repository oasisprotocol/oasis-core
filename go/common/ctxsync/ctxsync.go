// Package ctxsync contains some synchronization primitvies that are
// aware of a context becoming done and can bail on waits in that
// case.
package ctxsync

import (
	"context"
	"sync"
)

// CancelableCond is like sync.Cond, but you can wait with a context
// and bail when the context is done.
type CancelableCond struct {
	// L is held while observing or changing the condition
	L                sync.Locker
	closeOnBroadcast chan struct{}
}

// NewCancelableCond returns a new CancelableCond.
func NewCancelableCond(l sync.Locker) *CancelableCond {
	return &CancelableCond{
		L:                l,
		closeOnBroadcast: make(chan struct{}),
	}
}

// Broadcast wakes all goroutines waiting on c. The caller must hold
// c.L during the call.
func (c *CancelableCond) Broadcast() {
	close(c.closeOnBroadcast)
	c.closeOnBroadcast = make(chan struct{})
}

// Wait atomically unlocks c.L and suspends execution of the calling
// goroutine. After later resuming execution, Wait locks c.L before
// returning. Returns true if awoken by Broadcast or false if the
// context is done. Because c.L is not locked when Wait first resumes,
// the caller typically cannot assume that the condition is true when
// Wait returns. Instead, the caller should Wait in a loop.
func (c *CancelableCond) Wait(ctx context.Context) bool {
	closeOnBroadcast := c.closeOnBroadcast
	c.L.Unlock()
	ok := false
	select {
	case <-closeOnBroadcast:
		ok = true
	case <-ctx.Done():
	}
	c.L.Lock()
	return ok
}
