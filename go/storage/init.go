// Package storage implements the storage backend.
package storage

import (
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/badger"
	"github.com/oasislabs/ekiden/go/storage/cachingclient"
	"github.com/oasislabs/ekiden/go/storage/client"
	"github.com/oasislabs/ekiden/go/storage/leveldb"
	"github.com/oasislabs/ekiden/go/storage/memory"
)

const (
	cfgBackend             = "storage.backend"
	cfgDebugMockSigningKey = "storage.debug.mock_signing_key"
	cfgCrashEnabled        = "storage.crash.enabled"
	cfgLRUSize             = "storage.root_cache.lru_size"
	cfgLRUSlots            = "storage.root_cache.apply_lock_lru_slots"
	cfgInsecureSkipChecks  = "storage.debug.insecure_skip_checks"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, dataDir string, schedulerBackend scheduler.Backend,
	registryBackend registry.Backend, signingKey *signature.PrivateKey) (api.Backend, error) {
	var impl api.Backend
	var err error

	if viper.GetBool(cfgDebugMockSigningKey) {
		var keyTmp signature.PrivateKey
		if keyTmp, err = signature.NewPrivateKey(rand.Reader); err != nil {
			return nil, err
		}
		signingKey = &keyTmp
	}

	backend := viper.GetString(cfgBackend)
	lruSize := uint64(viper.GetSizeInBytes(cfgLRUSize))
	applyLockLRUSlots := uint64(viper.GetInt(cfgLRUSlots))
	insecureSkipChecks := viper.GetBool(cfgInsecureSkipChecks)

	switch strings.ToLower(backend) {
	case memory.BackendName:
		impl = memory.New(signingKey, insecureSkipChecks)
	case badger.BackendName:
		dbDir := filepath.Join(dataDir, badger.DBFile)
		impl, err = badger.New(dbDir, signingKey, lruSize, applyLockLRUSlots, insecureSkipChecks)
	case leveldb.BackendName:
		dbDir := filepath.Join(dataDir, leveldb.DBFile)
		impl, err = leveldb.New(dbDir, signingKey, lruSize, applyLockLRUSlots, insecureSkipChecks)
	case client.BackendName:
		impl, err = client.New(ctx, schedulerBackend, registryBackend)
	case cachingclient.BackendName:
		var remote api.Backend
		remote, err = client.New(ctx, schedulerBackend, registryBackend)
		if err != nil {
			return nil, err
		}
		impl, err = cachingclient.New(remote, insecureSkipChecks)
	default:
		err = fmt.Errorf("storage: unsupported backend: '%v'", backend)
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

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgBackend, memory.BackendName, "Storage backend")
		cmd.Flags().Bool(cfgDebugMockSigningKey, false, "Generate volatile mock signing key")
		cmd.Flags().Bool(cfgCrashEnabled, false, "Enable the crashing storage wrapper")
		cmd.Flags().String(cfgLRUSize, "128m", "Maximum LRU size in bytes to use in the MKVS tree root cache")
		cmd.Flags().Int(cfgLRUSlots, 1000, "How many LRU slots to use for Apply call locks in the MKVS tree root cache")

		cmd.Flags().Bool(cfgInsecureSkipChecks, false, "INSECURE: Skip known root checks")
		_ = cmd.Flags().MarkHidden(cfgInsecureSkipChecks)
	}

	for _, v := range []string{
		cfgBackend,
		cfgDebugMockSigningKey,
		cfgCrashEnabled,
		cfgLRUSize,
		cfgLRUSlots,
		cfgInsecureSkipChecks,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}

	client.RegisterFlags(cmd)
	cachingclient.RegisterFlags(cmd)
}
