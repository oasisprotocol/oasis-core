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
	"github.com/oasislabs/ekiden/go/storage/bolt"
	"github.com/oasislabs/ekiden/go/storage/memory"
)

const cfgBackend = "storage.backend"

var flagBackend string

// New constructs a new Backend based on the configuration flags.
func New(cmd *cobra.Command, timeSource epochtime.Backend, dataDir string) (api.Backend, error) {
	backend, _ := cmd.Flags().GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case memory.BackendName:
		return memory.New(timeSource), nil
	case bolt.BackendName:
		fn := filepath.Join(dataDir, bolt.DBFile)
		return bolt.New(fn, timeSource)
	default:
		return nil, fmt.Errorf("storage: unsupported backend: '%v'", backend)
	}
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
