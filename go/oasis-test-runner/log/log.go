// Package log provides utilities for watching log files.
package log

import (
	"fmt"
	"time"

	"github.com/hpcloud/tail"
	"github.com/hpcloud/tail/watch"
)

// WatcherHandlerFactory is a factory interface for log file watcher handlers.
type WatcherHandlerFactory interface {
	// New will create and return a WatcherHandler ready for use.
	New() (WatcherHandler, error)
}

// WatcherHandler is a log file watcher handler.
type WatcherHandler interface {
	// Line is called for each processed line.
	Line(string) error

	// Finish is called after the log file has been closed.
	Finish() error
}

// Watcher is a log file watcher.
type Watcher struct {
	name string

	tail  *tail.Tail
	errCh chan error
}

// WatcherConfig is a log file watcher configuration.
type WatcherConfig struct {
	Name string
	File string

	Handlers []WatcherHandler
}

// Name returns the log watcher name.
func (l *Watcher) Name() string {
	return l.name
}

// Cleanup stops watching the log.
func (l *Watcher) Cleanup() {
	if l.tail == nil {
		return
	}

	// Wait for two polling rounds to complete before stopping so that the watcher had the time to
	// process any remaining bits.
	time.Sleep(2 * watch.POLL_DURATION)

	_ = l.tail.Stop()
	l.tail = nil
}

// Errors returns a channel that is used to receive any errors
// encountered by the handlers while watching the log.
func (l *Watcher) Errors() <-chan error {
	return l.errCh
}

// NewWatcher creates a new log watcher.
func NewWatcher(cfg *WatcherConfig) (*Watcher, error) {
	tail, err := tail.TailFile(cfg.File, tail.Config{
		ReOpen: true,
		Poll:   true, // inotify can leak kernel resources...
		Follow: true,
		Logger: tail.DiscardingLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("log: failed to tail file: %w", err)
	}

	errCh := make(chan error)
	go func() {
		defer close(errCh)

		var err error
		for line := range tail.Lines {
			if l := line.Text; l != "" && err == nil {
				for _, h := range cfg.Handlers {
					if err = h.Line(l); err != nil {
						break
					}
				}
			}
		}
		if err == nil {
			for _, h := range cfg.Handlers {
				if err = h.Finish(); err != nil {
					break
				}
			}
		}

		errCh <- err
	}()

	return &Watcher{
		name:  cfg.Name,
		tail:  tail,
		errCh: errCh,
	}, nil
}
