package api

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

var (
	_ WriteLogIterator = (*staticWriteLogIterator)(nil)
	_ WriteLogIterator = (*PipeWriteLogIterator)(nil)

	// ErrWriteLogIteratorInvalid is raised when Value() is called on an iterator that finished already or hasn't started yet.
	ErrWriteLogIteratorInvalid = errors.New("urkel: write log iterator invalid")
)

const (
	// pipeIteratorQueueSize is the number of elements the pipe iterator can take before starting to block.
	pipeIteratorQueueSize = 100
)

// WriteLogIterator iterates over MKVS write log entries between two different storage instances.
type WriteLogIterator interface {
	// Next advances the iterator to the next element and returns false if there are no more elements.
	Next() (bool, error)
	// Value returns the log entry the iterator is currently pointing to.
	Value() (writelog.LogEntry, error)
}

type staticWriteLogIterator struct {
	cursor  int
	entries writelog.WriteLog
}

func (i *staticWriteLogIterator) Next() (bool, error) {
	i.cursor++
	if i.cursor >= len(i.entries) || len(i.entries) == 0 {
		return false, nil
	}
	return true, nil
}

func (i *staticWriteLogIterator) Value() (writelog.LogEntry, error) {
	if i.cursor < 0 || i.cursor >= len(i.entries) {
		return writelog.LogEntry{}, ErrWriteLogIteratorInvalid
	}
	return i.entries[i.cursor], nil
}

// NewStaticWriteLogIterator returns a new writelog iterator that's backed by a static in-memory array.
func NewStaticWriteLogIterator(writeLog writelog.WriteLog) WriteLogIterator {
	return &staticWriteLogIterator{
		cursor:  -1,
		entries: writeLog,
	}
}

// PipeWriteLogIterator is a queue-backed writelog iterator which can be asynchronously
// both pushed into and read from.
type PipeWriteLogIterator struct {
	queue  chan interface{}
	cached *writelog.LogEntry
	ctx    context.Context
}

func (i *PipeWriteLogIterator) Next() (bool, error) {
	select {
	case ret, ok := <-i.queue:
		if !ok {
			i.cached = nil
			return false, nil
		}
		switch obj := ret.(type) {
		case error:
			i.cached = nil
			return false, obj
		case *writelog.LogEntry:
			i.cached = obj
		}
		return true, nil
	case <-i.ctx.Done():
		return false, i.ctx.Err()
	}
}

func (i *PipeWriteLogIterator) Value() (writelog.LogEntry, error) {
	if i.cached == nil {
		return writelog.LogEntry{}, ErrWriteLogIteratorInvalid
	}
	return *i.cached, nil
}

func (i *PipeWriteLogIterator) Put(logEntry *writelog.LogEntry) error {
	select {
	case i.queue <- logEntry:
		return nil
	case <-i.ctx.Done():
		return i.ctx.Err()
	}
}

// PutError pushed an error to the iterator's read side.
func (i *PipeWriteLogIterator) PutError(err error) error {
	select {
	case i.queue <- err:
		return nil
	case <-i.ctx.Done():
		return i.ctx.Err()
	}
}

// Close signals an end of the log entry stream to the iterator's read side.
func (i *PipeWriteLogIterator) Close() {
	close(i.queue)
}

// NewPipeWriteLogIterator returns a new PipeWriteLogIterator.
func NewPipeWriteLogIterator(ctx context.Context) PipeWriteLogIterator {
	return PipeWriteLogIterator{
		queue: make(chan interface{}, pipeIteratorQueueSize),
		ctx:   ctx,
	}
}
