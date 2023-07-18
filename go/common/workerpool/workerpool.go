// Package workerpool implements a simple goroutine-based workerpool with a configurable number of workers.
package workerpool

import (
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/eapache/channels"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

type expBackoff struct {
	lock sync.Mutex

	backoff *backoff.ExponentialBackOff
	timeout time.Duration
}

func (b *expBackoff) Success() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.backoff.Reset()
	b.timeout = 0
}

func (b *expBackoff) Failure() {
	b.lock.Lock()
	defer b.lock.Unlock()

	b.timeout = b.backoff.NextBackOff()
}

func (b *expBackoff) Timeout() time.Duration {
	b.lock.Lock()
	defer b.lock.Unlock()

	return b.timeout
}

// BackoffConfig is the configuration for the backoff mechanism for the workers.
type BackoffConfig struct {
	// MinTimeout is the minimum timeout to wait in case of failures.
	MinTimeout time.Duration
	// MaxTimeout is the maximum timeout to wait in case of repeated failures.
	MaxTimeout time.Duration
}

type jobDescriptor struct {
	terminate  bool
	job        func() error
	completeCh chan struct{}
}

// Pool is a pool of goroutine workers.
//
// Notes:
//   - The pool is always constructed with one active worker goroutine.
//   - Once closed, it can not be used anymore.
type Pool struct { // nolint: maligned
	lock        sync.Mutex
	workerGroup sync.WaitGroup
	backoff     *expBackoff

	name string

	currentCount uint

	jobCh    *channels.InfiniteChannel
	stopCh   chan struct{}
	quitCh   chan struct{}
	stopOnce sync.Once

	logger *logging.Logger
}

// Resize sets the number of parallel goroutine workers to the number given.
//
// newCount must be greater than 0.
func (p *Pool) Resize(newCount uint) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if newCount == 0 {
		panic(fmt.Sprintf("workerpool/%s: pool must always have at least one worker", p.name))
	}

	if p.currentCount == 0 {
		panic(fmt.Sprintf("workerpool/%s: tried to resize stopped pool", p.name))
	}

	if newCount < p.currentCount {
		for i := p.currentCount; i > newCount; i-- {
			p.jobCh.In() <- &jobDescriptor{
				terminate: true,
			}
		}
	} else if newCount > p.currentCount {
		for i := p.currentCount; i < newCount; i++ {
			p.workerGroup.Add(1)
			go p.worker()
		}
	}

	p.currentCount = newCount
}

// Stop causes all worker goroutines to shut down.
//
// The pool must not be used for any further tasks after calling this method.
func (p *Pool) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.currentCount = 0
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})

	for range p.jobCh.Out() {
		// Clear the channel to close all go routines and prevent memory leaks.
	}
}

// Quit returns a channel that will be closed when the pool stops.
func (p *Pool) Quit() <-chan struct{} {
	return p.quitCh
}

// Submit adds a task to the pool's queue and returns a channel that will be closed
// once the task is complete.
func (p *Pool) Submit(job func() error) <-chan struct{} {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.currentCount == 0 {
		return nil
	}

	desc := &jobDescriptor{
		job:        job,
		completeCh: make(chan struct{}),
	}

	p.jobCh.In() <- desc
	return desc.completeCh
}

func (p *Pool) lifetimeManager() {
	p.workerGroup.Wait()
	p.jobCh.Close()
	close(p.quitCh)
}

func (p *Pool) worker() {
	defer p.workerGroup.Done()

	for {
		// Wait for the backoff period if configured.
		if p.backoff != nil {
			select {
			case <-p.stopCh:
				return
			case <-time.After(p.backoff.Timeout()):
			}
		}

		select {
		case <-p.stopCh:
			return
		case item, ok := <-p.jobCh.Out():
			if !ok {
				return
			}
			job := item.(*jobDescriptor)
			if job.terminate {
				return
			}
			err := job.job()
			// Submit backoff feedback if configured.
			if p.backoff != nil {
				switch err {
				case nil:
					p.backoff.Success()
				default:
					p.backoff.Failure()
				}
			}
			close(job.completeCh)
		}
	}
}

// PoolConfig is the configuration for a worker pool.
type PoolConfig struct {
	// Backoff is the (optional) backoff configuration.
	// Defaults to no backoff if unset.
	Backoff *BackoffConfig
}

// New creates and returns a new worker pool with one worker goroutine.
func New(name string, cfg *PoolConfig) *Pool {
	pool := &Pool{
		name:         name,
		currentCount: 1,
		jobCh:        channels.NewInfiniteChannel(),
		stopCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		logger:       logging.GetLogger(fmt.Sprintf("workerpool/%s", name)),
	}

	if cfg != nil && cfg.Backoff != nil {
		backoff := cmnBackoff.NewExponentialBackOff()
		backoff.InitialInterval = cfg.Backoff.MinTimeout
		backoff.MaxInterval = cfg.Backoff.MaxTimeout
		backoff.Reset()
		pool.backoff = &expBackoff{
			backoff: backoff,
		}
	}

	pool.workerGroup.Add(1)
	go pool.worker()
	go pool.lifetimeManager()

	return pool
}
