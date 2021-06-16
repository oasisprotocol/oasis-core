// Package badger contains convenience helpers for integrating BadgerDB.
package badger

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	badgerV2 "github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v3"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

const (
	gcInterval     = 5 * time.Minute
	gcDiscardRatio = 0.5

	migrationBufferSize      = 64 << 20 // 64 MiB
	migrationTemporarySuffix = ".migration"
	migrationBackupSuffix    = ".backup"
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

// Open returns a new DB object.
func Open(opts badger.Options) (*badger.DB, error) {
	return openWithMigrations(opts, false)
}

// OpenManaged returns a new DB object in managed mode.
func OpenManaged(opts badger.Options) (*badger.DB, error) {
	return openWithMigrations(opts, true)
}

func openWithMigrations(opts badger.Options, managed bool) (*badger.DB, error) {
	openFn := badger.Open
	if managed {
		openFn = badger.OpenManaged
	}

	db, err := openFn(opts)
	if err == nil {
		return db, nil
	}

	// Check if the error indicates that a migration is needed.
	// XXX: Since badger does not support indicating this via an exported error type, we need
	//      to resort to string matching which is not ideal.
	if !strings.Contains(err.Error(), "manifest has unsupported version") {
		return nil, err
	}

	// Perform the migration.
	if err := migrateDatabase(opts, managed); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Retry opening the database.
	return openFn(opts)
}

func migrateDatabase(opts badger.Options, managed bool) error {
	var logger *logging.Logger
	adapter, _ := opts.Logger.(*badgerLogger)
	if logger != nil {
		logger = adapter.logger
	} else {
		logger = logging.GetLogger("common/badger")
	}
	logger = logger.With("db", opts.Dir)

	logger.Warn("performing a database migration")

	// We don't use such a configuration anywhere, but make sure anyway.
	if opts.ValueDir != opts.Dir {
		return fmt.Errorf("migrations with separate value directory not yet supported")
	}

	// Remove any leftovers.
	temporaryDbName := opts.Dir + migrationTemporarySuffix
	if err := os.RemoveAll(temporaryDbName); err != nil {
		return fmt.Errorf("failed to remove temporary destination '%s': %w", temporaryDbName, err)
	}

	openFnV2 := badgerV2.Open
	openFnV3 := badger.Open
	if managed {
		openFnV2 = badgerV2.OpenManaged
		openFnV3 = badger.OpenManaged
	}

	// All non-managed databases used by oasis-core are configured to keep only one version.
	// Part of the migrator assumes this, therefore fail in case this is not the case.
	if !managed && opts.NumVersionsToKeep != 1 {
		return fmt.Errorf("migration assumes 1 version to keep for non-managed databases")
	}

	// Open the database as Badger v2.
	optsV2 := badgerV2.DefaultOptions(opts.Dir)
	optsV2 = optsV2.WithNumVersionsToKeep(opts.NumVersionsToKeep)
	optsV2 = optsV2.WithLogger(nil)

	dbV2, err := openFnV2(optsV2)
	if err != nil {
		return fmt.Errorf("failed to open source database: %w", err)
	}
	defer dbV2.Close()

	// Open the destination database as Badger v3.
	optsV3 := opts
	optsV3 = optsV3.WithDir(temporaryDbName)
	optsV3 = optsV3.WithValueDir(temporaryDbName)
	optsV3 = optsV3.WithNumGoroutines(viper.GetInt(cfgMigrateNumGoRoutines))

	dbV3, err := openFnV3(optsV3)
	if err != nil {
		return fmt.Errorf("failed to open destination database: %w", err)
	}
	defer dbV3.Close()

	r, w := io.Pipe()

	// Start the backup goroutine.
	backupCh := make(chan error, 1)
	go func() {
		defer close(backupCh)

		bw := bufio.NewWriterSize(w, migrationBufferSize)
		defer w.Close()
		defer bw.Flush()

		_, errBackup := backup(dbV2, bw, managed)
		backupCh <- errBackup
	}()

	// Start the restore process.
	if err := dbV3.Load(r, 256); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}
	if err := <-backupCh; err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	// Close both databases.
	dbV2.Close()
	dbV3.Close()

	// Rename old database to keep as a backup and rename new database in place of the old one.
	if err := os.Rename(opts.Dir, opts.Dir+migrationBackupSuffix); err != nil {
		return fmt.Errorf("failed to rename source database to '%s': %w", opts.Dir+migrationBackupSuffix, err)
	}
	if err := os.Rename(opts.Dir+migrationTemporarySuffix, opts.Dir); err != nil {
		return fmt.Errorf("failed to rename destination database to '%s': %w", opts.Dir, err)
	}

	logger.Warn("database successfully migrated")

	return nil
}
