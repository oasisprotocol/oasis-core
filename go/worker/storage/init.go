// Package storage implements the storage backend.
package storage

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"

	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
)

const (
	// CfgWorkerEnabled enables the storage worker.
	CfgWorkerEnabled      = "worker.storage.enabled"
	cfgWorkerFetcherCount = "worker.storage.fetcher_count"

	// CfgWorkerCheckpointerDisabled disables the storage checkpointer.
	CfgWorkerCheckpointerDisabled = "worker.storage.checkpointer.disabled"
	// CfgWorkerCheckpointCheckInterval configures the checkpointer check interval.
	CfgWorkerCheckpointCheckInterval = "worker.storage.checkpointer.check_interval"

	// CfgCheckpointSyncDisabled disables syncing from checkpoints on worker startup.
	CfgWorkerCheckpointSyncDisabled = "worker.storage.checkpoint_sync.disabled"

	// CfgWorkerDebugIgnoreApply is a debug option that makes the worker ignore
	// all apply operations.
	CfgWorkerDebugIgnoreApply = "worker.debug.storage.ignore_apply"

	// CfgBackend configures the storage backend flag.
	CfgBackend = "worker.storage.backend"

	// CfgLRUSlots configures the LRU apply lock slots.
	CfgLRUSlots = "worker.storage.root_cache.apply_lock_lru_slots"

	// CfgMaxCacheSize configures the maximum in-memory cache size.
	CfgMaxCacheSize = "worker.storage.max_cache_size"

	cfgCrashEnabled = "worker.storage.crash.enabled"

	// CfgInsecureSkipChecks disables known root checks.
	CfgInsecureSkipChecks = "worker.storage.debug.insecure_skip_checks"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// GetLocalBackendDBDir returns the database name for local backends.
func GetLocalBackendDBDir(dataDir, backend string) string {
	return filepath.Join(dataDir, database.DefaultFileName(backend))
}

// NewLocalBackend constructs a new Backend based on the configuration flags.
func NewLocalBackend(
	dataDir string,
	namespace common.Namespace,
	identity *identity.Identity,
) (api.LocalBackend, error) {
	cfg := &api.Config{
		Backend:            strings.ToLower(viper.GetString(CfgBackend)),
		DB:                 dataDir,
		Signer:             identity.NodeSigner,
		ApplyLockLRUSlots:  uint64(viper.GetInt(CfgLRUSlots)),
		InsecureSkipChecks: viper.GetBool(CfgInsecureSkipChecks) && cmdFlags.DebugDontBlameOasis(),
		Namespace:          namespace,
		MaxCacheSize:       int64(viper.GetSizeInBytes(CfgMaxCacheSize)),
	}

	var (
		err  error
		impl api.Backend
	)
	switch cfg.Backend {
	case database.BackendNameBadgerDB:
		cfg.DB = GetLocalBackendDBDir(dataDir, cfg.Backend)
		impl, err = database.New(cfg)
	default:
		err = fmt.Errorf("storage: unsupported backend: '%v'", cfg.Backend)
	}
	if err != nil {
		return nil, err
	}

	crashEnabled := viper.GetBool(cfgCrashEnabled) && cmdFlags.DebugDontBlameOasis()
	if crashEnabled {
		impl = newCrashingWrapper(impl)
	}

	return api.NewMetricsWrapper(impl), nil
}

func init() {
	Flags.Bool(CfgWorkerEnabled, false, "Enable storage worker")
	Flags.Uint(cfgWorkerFetcherCount, 4, "Number of concurrent storage diff fetchers")
	Flags.Bool(CfgWorkerCheckpointerDisabled, false, "Disable the storage checkpointer")
	Flags.Duration(CfgWorkerCheckpointCheckInterval, 1*time.Minute, "Storage checkpointer check interval")
	Flags.Bool(CfgWorkerCheckpointSyncDisabled, false, "Disable initial storage sync from checkpoints")

	Flags.Bool(CfgWorkerDebugIgnoreApply, false, "Ignore Apply operations (for debugging purposes)")
	_ = Flags.MarkHidden(CfgWorkerDebugIgnoreApply)

	Flags.String(CfgBackend, database.BackendNameBadgerDB, "Storage backend")
	Flags.Bool(cfgCrashEnabled, false, "Enable the crashing storage wrapper")
	Flags.Int(CfgLRUSlots, 1000, "How many LRU slots to use for Apply call locks in the MKVS tree root cache")
	Flags.String(CfgMaxCacheSize, "64mb", "Maximum in-memory cache size")

	Flags.Bool(CfgInsecureSkipChecks, false, "INSECURE: Skip known root checks")

	_ = Flags.MarkHidden(CfgInsecureSkipChecks)
	_ = Flags.MarkHidden(cfgCrashEnabled)

	_ = viper.BindPFlags(Flags)
}
