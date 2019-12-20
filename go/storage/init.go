// Package storage implements the storage backend.
package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/identity"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/client"
	"github.com/oasislabs/oasis-core/go/storage/database"
)

const (
	// CfgBackend configures the storage backend flag.
	CfgBackend      = "storage.backend"
	cfgCrashEnabled = "storage.crash.enabled"
	// CfgLRUSlots configures the LRU apply lock slots.
	CfgLRUSlots           = "storage.root_cache.apply_lock_lru_slots"
	cfgInsecureSkipChecks = "storage.debug.insecure_skip_checks"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	schedulerBackend scheduler.Backend,
	registryBackend registry.Backend,
) (api.Backend, error) {
	cfg := &api.Config{
		Backend:            strings.ToLower(viper.GetString(CfgBackend)),
		DB:                 dataDir,
		Signer:             identity.NodeSigner,
		ApplyLockLRUSlots:  uint64(viper.GetInt(CfgLRUSlots)),
		InsecureSkipChecks: viper.GetBool(cfgInsecureSkipChecks) && cmdFlags.DebugDontBlameOasis(),
	}

	var (
		err  error
		impl api.Backend
	)
	switch cfg.Backend {
	case database.BackendNameBadgerDB:
		cfg.DB = filepath.Join(cfg.DB, database.DefaultFileName(cfg.Backend))
		impl, err = database.New(cfg)
	case client.BackendName:
		impl, err = client.New(ctx, identity, schedulerBackend, registryBackend)
	default:
		err = fmt.Errorf("storage: unsupported backend: '%v'", cfg.Backend)
	}

	crashEnabled := viper.GetBool(cfgCrashEnabled) && cmdFlags.DebugDontBlameOasis()
	if crashEnabled {
		impl = newCrashingWrapper(impl)
	}

	if err != nil {
		return nil, err
	}

	return newMetricsWrapper(impl), nil
}

func init() {
	Flags.String(CfgBackend, database.BackendNameBadgerDB, "Storage backend")
	Flags.Bool(cfgCrashEnabled, false, "Enable the crashing storage wrapper")
	Flags.Int(CfgLRUSlots, 1000, "How many LRU slots to use for Apply call locks in the MKVS tree root cache")

	Flags.Bool(cfgInsecureSkipChecks, false, "INSECURE: Skip known root checks")

	_ = Flags.MarkHidden(cfgInsecureSkipChecks)
	_ = Flags.MarkHidden(cfgCrashEnabled)

	_ = viper.BindPFlags(Flags)

	Flags.AddFlagSet(client.Flags)
}
