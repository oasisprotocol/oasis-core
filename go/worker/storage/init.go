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
	cfgWorkerFetcherCount = "worker.storage.fetcher_count"

	// CfgWorkerPublicRPCEnabled enables storage state access for all nodes instead of just
	// storage committee members.
	CfgWorkerPublicRPCEnabled = "worker.storage.public_rpc.enabled"

	// CfgWorkerCheckpointerEnabled enables the storage checkpointer.
	CfgWorkerCheckpointerEnabled = "worker.storage.checkpointer.enabled"
	// CfgWorkerCheckpointCheckInterval configures the checkpointer check interval.
	CfgWorkerCheckpointCheckInterval = "worker.storage.checkpointer.check_interval"

	// CfgWorkerCheckpointSyncDisabled disables syncing from checkpoints on worker startup.
	CfgWorkerCheckpointSyncDisabled = "worker.storage.checkpoint_sync.disabled"

	// CfgBackend configures the storage backend flag.
	CfgBackend = "worker.storage.backend"

	// CfgMaxCacheSize configures the maximum in-memory cache size.
	CfgMaxCacheSize = "worker.storage.max_cache_size"

	cfgCrashEnabled = "worker.storage.crash.enabled"
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
		Backend:      strings.ToLower(viper.GetString(CfgBackend)),
		DB:           dataDir,
		Namespace:    namespace,
		MaxCacheSize: int64(viper.GetSizeInBytes(CfgMaxCacheSize)),
	}

	var (
		err  error
		impl api.LocalBackend
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

	return api.NewMetricsWrapper(impl).(api.LocalBackend), nil
}

func init() {
	Flags.Uint(cfgWorkerFetcherCount, 4, "Number of concurrent storage diff fetchers")
	Flags.Bool(CfgWorkerPublicRPCEnabled, false, "Enable storage RPC access for all nodes")
	Flags.Bool(CfgWorkerCheckpointerEnabled, false, "Enable the storage checkpointer")
	Flags.Duration(CfgWorkerCheckpointCheckInterval, 1*time.Minute, "Storage checkpointer check interval")
	Flags.Bool(CfgWorkerCheckpointSyncDisabled, false, "Disable initial storage sync from checkpoints")

	Flags.String(CfgBackend, database.BackendNameBadgerDB, "Storage backend")
	Flags.String(CfgMaxCacheSize, "64mb", "Maximum in-memory cache size")

	Flags.Bool(cfgCrashEnabled, false, "UNSAFE: Enable the crashing storage wrapper")
	_ = Flags.MarkHidden(cfgCrashEnabled)

	_ = viper.BindPFlags(Flags)
}
