package log

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/nxadm/tail"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

// Log is a log file handle.
//
// It implements `io.Writer` so it can be used as the log handler and it also provides methods for
// streaming the content of the log.
type Log struct {
	mu      sync.Mutex
	file    *os.File
	closeCh chan struct{}

	maxSize     int
	currentSize int
}

func newLog(fn string, maxSize int) (*Log, error) {
	file, err := os.OpenFile(fn, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}

	return &Log{
		file:    file,
		closeCh: make(chan struct{}),
		maxSize: maxSize,
	}, nil
}

// Write writes the given buffer into the log file.
//
// In case the total written size exceeds the configured maximum, the log file is rotated.
func (l *Log) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.currentSize >= l.maxSize {
		if err := l.maybeRotate(); err != nil {
			return 0, err
		}
	}

	n, err := l.file.Write(b)
	l.currentSize += n
	return n, err
}

func (l *Log) maybeRotate() error {
	// Close and remove the file instead of truncating it so that any readers can finish reading.
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("failed to close file for rotation: %w", err)
	}
	if err := os.Remove(l.file.Name()); err != nil {
		return fmt.Errorf("failed to remove file for rotation: %w", err)
	}

	file, err := os.OpenFile(l.file.Name(), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to reopen file for rotation: %w", err)
	}
	l.file = file
	l.currentSize = 0
	return nil
}

// Close closes the log file for writing.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer close(l.closeCh)
	return l.file.Close()
}

// Watch starts watching the log file for changes, pushing lines to the passed channel.
func (l *Log) Watch(ctx context.Context, ch chan<- string, follow bool) error {
	watcher, err := tail.TailFile(l.file.Name(), tail.Config{
		ReOpen:        follow,
		Follow:        follow,
		CompleteLines: true,
	})
	if err != nil {
		return err
	}
	defer watcher.Stop() //nolint: errcheck

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.closeCh:
			return nil
		case line, ok := <-watcher.Lines:
			if !ok {
				return nil
			}

			ch <- line.Text
		}
	}
}

// runtimeExcludeFields are the fields to exclude in per-runtime logs.
var runtimeExcludeFields = map[any]struct{}{
	"runtime_id":   {},
	"component":    {},
	"provisioner":  {},
	"runtime_name": {},
}

// Logger returns a logger backed by this log file handle.
func (l *Log) Logger() *logging.Logger {
	logger := logging.NewJSONLogger(l)
	logger = logging.NewFilterLogger(logger, runtimeExcludeFields)
	return logger
}
