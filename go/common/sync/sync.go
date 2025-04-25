// Package sync provides sync primitives.
package sync

import (
	"context"
)

// One is an object that will allow to run only one function at a time.
type One interface {
	// TryStart starts the function iff no other is running.
	TryStart(func(context.Context)) bool

	// TryStop stops the running function, if any. This method blocks until
	// the function finishes its work.
	TryStop() bool

	// IsRunning returns true iff the function is running.
	IsRunning() bool
}

type one struct {
	// startCh allows only one function being ran at a time.
	startCh chan struct{}

	// ctrlCh gives control over the running function.
	ctrlCh chan struct {
		// cancel stops the running function by canceling the context.
		cancel context.CancelFunc
		// doneCh is closed when the running function finishes.
		doneCh chan struct{}
	}
}

// NewOne creates an object which will allow to run only one function at a time.
func NewOne() One {
	return &one{
		startCh: make(chan struct{}, 1),
		ctrlCh: make(chan struct {
			cancel context.CancelFunc
			doneCh chan struct{}
		}, 1),
	}
}

// TryStart implements One.
func (s *one) TryStart(fn func(ctx context.Context)) bool {
	// Allow running only one function at a time.
	select {
	case s.startCh <- struct{}{}:
	default:
		return false
	}

	ctx, cancel := context.WithCancel(context.Background())

	ctrl := struct {
		cancel context.CancelFunc
		doneCh chan struct{}
	}{
		cancel: cancel,
		doneCh: make(chan struct{}),
	}
	s.ctrlCh <- ctrl

	go func() {
		fn(ctx)

		select {
		case <-s.ctrlCh:
		default:
		}

		close(ctrl.doneCh)

		// Allow next function to run.
		<-s.startCh
	}()

	return true
}

// TryStop implements One.
func (s *one) TryStop() bool {
	select {
	case ctrl := <-s.ctrlCh:
		ctrl.cancel()
		<-ctrl.doneCh
		return true

	default:
		return false
	}
}

// IsRunning implements One.
func (s *one) IsRunning() bool {
	return len(s.startCh) > 0
}
