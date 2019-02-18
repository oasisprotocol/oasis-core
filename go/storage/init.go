// Package storage implements the storage backend.
package storage

import (
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
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
func New(timeSource epochtime.Backend, dataDir string, signingKey *signature.PrivateKey) (api.Backend, error) {
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
		impl = memory.New(timeSource, signingKey)
	case leveldb.BackendName:
		fn := filepath.Join(dataDir, leveldb.DBFile)
		impl, err = leveldb.New(fn, timeSource, signingKey)
	case client.BackendName:
		impl, err = client.New()
	case cachingclient.BackendName:
		var remote api.Backend
		remote, err = client.New()
		if err == nil {
			impl, err = cachingclient.New(remote)
		}
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
