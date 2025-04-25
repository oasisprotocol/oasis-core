package sync

import (
	"sync"
	"sync/atomic"
)

// FallibleOnce is similar to `sync.Once` but supports returning an error and retrying in case the
// function does not succeed.
type FallibleOnce struct {
	done atomic.Uint32
	m    sync.Mutex
}

// Do executes the given function exactly once, unless the function returns an error. In case an
// error is returned, the function will be executed again on the next invocation of `Do`.
func (o *FallibleOnce) Do(f func() error) error {
	if o.Done() {
		return nil
	}
	return o.doSlow(f)
}

// Done returns true if the function has been executed successfully without error.
//
// If it returns false, the function's execution status is uncertain. The function may have been
// executed successfully, may be in progress, or may not have been executed successfully at all.
func (o *FallibleOnce) Done() bool {
	return o.done.Load() != 0
}

func (o *FallibleOnce) doSlow(f func() error) error {
	o.m.Lock()
	defer o.m.Unlock()
	if o.Done() {
		return nil
	}
	if err := f(); err != nil {
		return err
	}
	o.done.Store(1)
	return nil
}
