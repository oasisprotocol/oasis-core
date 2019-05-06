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
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/cachingclient"
	"github.com/oasislabs/ekiden/go/storage/client"
	"github.com/oasislabs/ekiden/go/storage/leveldb"
	"github.com/oasislabs/ekiden/go/storage/memory"
)

const (
	cfgBackend             = "storage.backend"
	cfgDebugMockSigningKey = "storage.debug.mock_signing_key"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, dataDir string, epochtimeBackend epochtime.Backend, schedulerBackend scheduler.Backend,
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
	switch strings.ToLower(backend) {
	case memory.BackendName:
		impl = memory.New(epochtimeBackend, signingKey)
	case leveldb.BackendName:
		dbDir := filepath.Join(dataDir, leveldb.DBFile)
		mkvsDBDir := filepath.Join(dataDir, leveldb.MKVSDBFile)
		impl, err = leveldb.New(dbDir, mkvsDBDir, epochtimeBackend, signingKey)
	case client.BackendName:
		impl, err = client.New(ctx, epochtimeBackend, schedulerBackend, registryBackend)
	case cachingclient.BackendName:
		var remote api.Backend
		remote, err = client.New(ctx, epochtimeBackend, schedulerBackend, registryBackend)
		if err != nil {
			return nil, err
		}
		impl, err = cachingclient.New(remote)
	default:
		err = fmt.Errorf("storage: unsupported backend: '%v'", backend)
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
	}

	for _, v := range []string{
		cfgBackend,
		cfgDebugMockSigningKey,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}

	client.RegisterFlags(cmd)
	cachingclient.RegisterFlags(cmd)
}
