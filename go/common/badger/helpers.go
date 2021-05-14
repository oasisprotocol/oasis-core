// Package badger contains convenience helpers for integrating BadgerDB.
package badger

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

const (
	gcInterval     = 5 * time.Minute
	gcDiscardRatio = 0.5
)

// NewLogAdapter returns a badger.Logger backed by an oasis-node logger.
func NewLogAdapter(logger *logging.Logger) badger.Logger {
	return &badgerLogger{
		logger: logger,
	}
}

type badgerLogger struct {
	logger *logging.Logger
}

func (l *badgerLogger) Errorf(format string, a ...interface{}) {
	l.logger.Error(strings.TrimSpace(fmt.Sprintf(format, a...)))
}

func (l *badgerLogger) Warningf(format string, a ...interface{}) {
	l.logger.Warn(strings.TrimSpace(fmt.Sprintf(format, a...)))
}

func (l *badgerLogger) Infof(format string, a ...interface{}) {
	l.logger.Info(strings.TrimSpace(fmt.Sprintf(format, a...)))
}

func (l *badgerLogger) Debugf(format string, a ...interface{}) {
	l.logger.Debug(strings.TrimSpace(fmt.Sprintf(format, a...)))
}

// GCWorker is a BadgerDB value log GC worker.
type GCWorker struct {
	logger *logging.Logger

	db *badger.DB

	closeOnce sync.Once
	closeCh   chan struct{}
	closedCh  chan struct{}
}

// Close halts the GC worker.
func (gc *GCWorker) Close() {
	gc.closeOnce.Do(func() {
		close(gc.closeCh)
		<-gc.closedCh
	})
}

func (gc *GCWorker) worker() {
	defer close(gc.closedCh)

	ticker := time.NewTicker(gcInterval)
	defer ticker.Stop()

	doGC := func() error {
		for {
			if err := gc.db.RunValueLogGC(gcDiscardRatio); err != nil {
				return err
			}
		}
	}

	for {
		select {
		case <-gc.closeCh:
			return
		case <-ticker.C:
		}

		// Run the value log GC.
		err := doGC()
		switch err {
		case nil, badger.ErrNoRewrite:
		default:
			gc.logger.Error("failed to GC value log",
				"err", err,
			)
		}
	}
}

// NewGCWorker creates a new BadgerDB value log GC worker for the provided
// db, logging to the specified logger.
func NewGCWorker(logger *logging.Logger, db *badger.DB) *GCWorker {
	gc := &GCWorker{
		logger:   logger,
		db:       db,
		closeCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}

	go gc.worker()

	return gc
}
