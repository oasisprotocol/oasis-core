package ctxsync

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWake(t *testing.T) {
	readyCh := make(chan struct{})
	doneCh := make(chan struct{})
	c := NewCancelableCond(new(sync.Mutex))
	ctx := context.Background()
	go func() {
		c.L.Lock()
		readyCh <- struct{}{}
		ok := c.Wait(ctx)
		c.L.Unlock()
		require.True(t, ok, "Wait canceled")
		doneCh <- struct{}{}
	}()
	<-readyCh
	c.L.Lock()
	c.Broadcast()
	c.L.Unlock()
	<-doneCh
}

func TestCancelEarly(t *testing.T) {
	c := NewCancelableCond(new(sync.Mutex))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.L.Lock()
	ok := c.Wait(ctx)
	c.L.Unlock()
	require.False(t, ok, "Wait finished")
}

func TestCancelLate(t *testing.T) {
	readyCh := make(chan struct{})
	doneCh := make(chan struct{})
	c := NewCancelableCond(new(sync.Mutex))
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c.L.Lock()
		readyCh <- struct{}{}
		ok := c.Wait(ctx)
		c.L.Unlock()
		require.False(t, ok, "Wait finished")
		doneCh <- struct{}{}
	}()
	<-readyCh
	c.L.Lock()
	cancel()
	c.L.Unlock()
	<-doneCh
}
