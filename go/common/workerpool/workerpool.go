// Package workerpool implements a simple goroutine-based workerpool with a configurable number of workers.
package workerpool

import (
	"fmt"
	"sync"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

type jobDescriptor struct {
	terminate  bool
	job        func()
	completeCh chan struct{}
}

// Pool is a pool of goroutine workers.
//
// Notes:
//  * The pool is always constructed with one active worker goroutine.
//  * Once closed, it can not be used anymore.
type Pool struct { // nolint: maligned
	lock        sync.Mutex
	workerGroup sync.WaitGroup

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
}

// Quit returns a channel that will be closed when the pool stops.
func (p *Pool) Quit() <-chan struct{} {
	return p.quitCh
}

// Submit adds a task to the pool's queue and returns a channel that will be closed
// once the task is complete.
func (p *Pool) Submit(job func()) <-chan struct{} {
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
			job.job()
			close(job.completeCh)
		}
	}
}

// New creates and returns a new worker pool with one worker goroutine.
func New(name string) *Pool {
	pool := &Pool{
		name:         name,
		currentCount: 1,
		jobCh:        channels.NewInfiniteChannel(),
		stopCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		logger:       logging.GetLogger(fmt.Sprintf("workerpool/%s", name)),
	}

	pool.workerGroup.Add(1)
	go pool.worker()
	go pool.lifetimeManager()

	return pool
}
