package writelog

import (
	"context"
	"errors"
)

var (
	_ Iterator = (*staticIterator)(nil)
	_ Iterator = (*PipeIterator)(nil)

	// ErrIteratorInvalid is raised when Value() is called on an iterator that finished already or hasn't started yet.
	ErrIteratorInvalid = errors.New("mkvs: write log iterator invalid")
)

const (
	// pipeIteratorQueueSize is the number of elements the pipe iterator can take before starting to block.
	pipeIteratorQueueSize = 100
)

// Iterator iterates over MKVS write log entries between two different storage instances.
type Iterator interface {
	// Next advances the iterator to the next element and returns false if there are no more elements.
	Next() (bool, error)
	// Value returns the log entry the iterator is currently pointing to.
	Value() (LogEntry, error)
}

type staticIterator struct {
	cursor  int
	entries WriteLog
}

func (i *staticIterator) Next() (bool, error) {
	i.cursor++
	if i.cursor >= len(i.entries) || len(i.entries) == 0 {
		return false, nil
	}
	return true, nil
}

func (i *staticIterator) Value() (LogEntry, error) {
	if i.cursor < 0 || i.cursor >= len(i.entries) {
		return LogEntry{}, ErrIteratorInvalid
	}
	return i.entries[i.cursor], nil
}

// NewStaticIterator returns a new writelog iterator that's backed by a static in-memory array.
func NewStaticIterator(writeLog WriteLog) Iterator {
	return &staticIterator{
		cursor:  -1,
		entries: writeLog,
	}
}

// PipeIterator is a queue-backed writelog iterator which can be asynchronously
// both pushed into and read from.
type PipeIterator struct {
	queue  chan interface{}
	cached *LogEntry
	ctx    context.Context
}

func (i *PipeIterator) Next() (bool, error) {
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
		case *LogEntry:
			i.cached = obj
		}
		return true, nil
	case <-i.ctx.Done():
		return false, i.ctx.Err()
	}
}

func (i *PipeIterator) Value() (LogEntry, error) {
	if i.cached == nil {
		return LogEntry{}, ErrIteratorInvalid
	}
	return *i.cached, nil
}

func (i *PipeIterator) Put(logEntry *LogEntry) error {
	select {
	case i.queue <- logEntry:
		return nil
	case <-i.ctx.Done():
		return i.ctx.Err()
	}
}

// PutError pushed an error to the iterator's read side.
func (i *PipeIterator) PutError(err error) error {
	select {
	case i.queue <- err:
		return nil
	case <-i.ctx.Done():
		return i.ctx.Err()
	}
}

// Close signals an end of the log entry stream to the iterator's read side.
func (i *PipeIterator) Close() {
	close(i.queue)
}

// NewPipeIterator returns a new PipeIterator.
func NewPipeIterator(ctx context.Context) PipeIterator {
	return PipeIterator{
		queue: make(chan interface{}, pipeIteratorQueueSize),
		ctx:   ctx,
	}
}

// DrainIterator drains the iterator, discarding all values.
func DrainIterator(it Iterator) error {
	for {
		more, err := it.Next()
		if !more || err != nil {
			return err
		}
	}
}
