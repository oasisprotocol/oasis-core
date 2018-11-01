// Package storage implements the storage backend.
package storage

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/leveldb"
	"github.com/oasislabs/ekiden/go/storage/memory"
)

const cfgBackend = "storage.backend"

var flagBackend string

// New constructs a new Backend based on the configuration flags.
func New(cmd *cobra.Command, timeSource epochtime.Backend, dataDir string) (api.Backend, error) {
	var impl api.Backend
	var err error

	backend, _ := cmd.Flags().GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case memory.BackendName:
		impl = memory.New(timeSource)
	case leveldb.BackendName:
		fn := filepath.Join(dataDir, leveldb.DBFile)
		impl, err = leveldb.New(fn, timeSource)
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
	cmd.Flags().StringVar(&flagBackend, cfgBackend, memory.BackendName, "Storage backend")

	for _, v := range []string{
		cfgBackend,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
