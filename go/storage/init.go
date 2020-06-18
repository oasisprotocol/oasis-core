// Package storage implements the storage backend.
package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/client"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
)

const (
	// CfgBackend configures the storage backend flag.
	CfgBackend = "storage.backend"

	// CfgLRUSlots configures the LRU apply lock slots.
	CfgLRUSlots = "storage.root_cache.apply_lock_lru_slots"

	// CfgMaxCacheSize configures the maximum in-memory cache size.
	CfgMaxCacheSize = "storage.max_cache_size"

	cfgCrashEnabled       = "storage.crash.enabled"
	cfgInsecureSkipChecks = "storage.debug.insecure_skip_checks"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

type options struct {
	consensus consensus.Backend
	runtime   registry.RuntimeDescriptorProvider
}

// Option is a storage configuration option.
type Option func(o *options)

// WithConsensus configures the consensus backend to use with storage backends which require access
// to the consensus layer. In case this option is not specified using such backends will fail.
func WithConsensus(consensus consensus.Backend) Option {
	return func(o *options) {
		o.consensus = consensus
	}
}

// WithRuntime configures the runtime to use for looking up storage parameters. In case this option
// is not specified default safe values will be used.
func WithRuntime(runtime registry.RuntimeDescriptorProvider) Option {
	return func(o *options) {
		o.runtime = runtime
	}
}

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	dataDir string,
	namespace common.Namespace,
	identity *identity.Identity,
	opts ...Option,
) (api.Backend, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	cfg := &api.Config{
		Backend:            strings.ToLower(viper.GetString(CfgBackend)),
		DB:                 dataDir,
		Signer:             identity.NodeSigner,
		ApplyLockLRUSlots:  uint64(viper.GetInt(CfgLRUSlots)),
		InsecureSkipChecks: viper.GetBool(cfgInsecureSkipChecks) && cmdFlags.DebugDontBlameOasis(),
		Namespace:          namespace,
		MaxCacheSize:       int64(viper.GetSizeInBytes(CfgMaxCacheSize)),
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
		if o.consensus == nil {
			return nil, fmt.Errorf("storage: backend '%s' requires a consensus backend to be set", cfg.Backend)
		}
		impl, err = client.New(ctx, namespace, identity, o.consensus.Scheduler(), o.consensus.Registry(), o.runtime)
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

	return newMetricsWrapper(impl), nil
}

func init() {
	Flags.String(CfgBackend, database.BackendNameBadgerDB, "Storage backend")
	Flags.Bool(cfgCrashEnabled, false, "Enable the crashing storage wrapper")
	Flags.Int(CfgLRUSlots, 1000, "How many LRU slots to use for Apply call locks in the MKVS tree root cache")
	Flags.String(CfgMaxCacheSize, "64mb", "Maximum in-memory cache size")

	Flags.Bool(cfgInsecureSkipChecks, false, "INSECURE: Skip known root checks")

	_ = Flags.MarkHidden(cfgInsecureSkipChecks)
	_ = Flags.MarkHidden(cfgCrashEnabled)

	_ = viper.BindPFlags(Flags)
}
