// Package log provides utilities for watching log files.
package log

import (
	"github.com/hpcloud/tail"
	"github.com/pkg/errors"
)

// Watcher is a log file watcher.
type Watcher struct {
	name string

	tail *tail.Tail
}

// WatcherConfig is a log file watcher configuration.
type WatcherConfig struct {
	Name string
	File string

	Handlers []func(string) error
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

	_ = l.tail.Stop()
	l.tail = nil
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
		return nil, errors.Wrap(err, "log: failed to tail file")
	}

	go func() {
		var err error
		for line := range tail.Lines {
			if l := line.Text; l != "" && err == nil {
				for _, fn := range cfg.Handlers {
					if err = fn(l); err != nil {
						break
					}
				}
			}
		}
	}()

	return &Watcher{
		name: cfg.Name,
		tail: tail,
	}, nil
}
