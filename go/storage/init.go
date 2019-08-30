// Package storage implements the storage backend.
package storage

import (
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/common/identity"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/cachingclient"
	"github.com/oasislabs/ekiden/go/storage/client"
	"github.com/oasislabs/ekiden/go/storage/database"
)

const (
	cfgBackend             = "storage.backend"
	cfgDebugMockSigningKey = "storage.debug.mock_signing_key"
	cfgCrashEnabled        = "storage.crash.enabled"
	cfgLRUSlots            = "storage.root_cache.apply_lock_lru_slots"
	cfgInsecureSkipChecks  = "storage.debug.insecure_skip_checks"
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
		Backend:            strings.ToLower(viper.GetString(cfgBackend)),
		DB:                 dataDir,
		Signer:             identity.NodeSigner,
		ApplyLockLRUSlots:  uint64(viper.GetInt(cfgLRUSlots)),
		InsecureSkipChecks: viper.GetBool(cfgInsecureSkipChecks),
	}

	var err error
	if viper.GetBool(cfgDebugMockSigningKey) {
		cfg.Signer, err = memorySigner.NewSigner(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	var impl api.Backend
	switch cfg.Backend {
	case database.BackendNameLevelDB, database.BackendNameBadgerDB:
		cfg.DB = filepath.Join(cfg.DB, database.DefaultFileName(cfg.Backend))
		impl, err = database.New(cfg)
	case client.BackendName:
		impl, err = client.New(ctx, identity, schedulerBackend, registryBackend)
	case cachingclient.BackendName:
		var remote api.Backend
		remote, err = client.New(ctx, identity, schedulerBackend, registryBackend)
		if err != nil {
			return nil, err
		}
		impl, err = cachingclient.New(remote, cfg.InsecureSkipChecks)
	default:
		err = fmt.Errorf("storage: unsupported backend: '%v'", cfg.Backend)
	}

	crashEnabled := viper.GetBool(cfgCrashEnabled)
	if crashEnabled {
		impl = newCrashingWrapper(impl)
	}

	if err != nil {
		return nil, err
	}

	return newMetricsWrapper(impl), nil
}

func init() {
	Flags.String(cfgBackend, database.BackendNameLevelDB, "Storage backend")
	Flags.Bool(cfgDebugMockSigningKey, false, "Generate volatile mock signing key")
	Flags.Bool(cfgCrashEnabled, false, "Enable the crashing storage wrapper")
	Flags.Int(cfgLRUSlots, 1000, "How many LRU slots to use for Apply call locks in the MKVS tree root cache")

	Flags.Bool(cfgInsecureSkipChecks, false, "INSECURE: Skip known root checks")
	_ = Flags.MarkHidden(cfgInsecureSkipChecks)

	_ = viper.BindPFlags(Flags)

	Flags.AddFlagSet(client.Flags)
	Flags.AddFlagSet(cachingclient.Flags)
}
