// Package storage implements the storage backend.
package storage

import (
	"fmt"
	"path/filepath"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/config"

	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
)

const cfgCrashEnabled = "worker.storage.crash.enabled"

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
) (api.LocalBackend, error) {
	cfg := &api.Config{
		Backend:      strings.ToLower(config.GlobalConfig.Storage.Backend),
		DB:           dataDir,
		Namespace:    namespace,
		MaxCacheSize: int64(config.ParseSizeInBytes(config.GlobalConfig.Storage.MaxCacheSize)),
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
	Flags.Bool(cfgCrashEnabled, false, "UNSAFE: Enable the crashing storage wrapper")
	_ = Flags.MarkHidden(cfgCrashEnabled)

	_ = viper.BindPFlags(Flags)
}
