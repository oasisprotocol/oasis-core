package storage

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
)

const (
	cfgBackend = "storage.backend"

	backendMemory = "memory"
	backendBolt   = "bolt"
)

var flagBackend string

// New constructs a new Backend based on the configuration flags.
func New(cmd *cobra.Command, timeSource epochtime.Backend, dataDir string) (Backend, error) {
	backend, _ := cmd.Flags().GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case backendMemory:
		return NewMemoryBackend(timeSource), nil
	case backendBolt:
		fn := filepath.Join(dataDir, boltDBFile)
		return NewBoltBackend(fn, timeSource)
	default:
		return nil, fmt.Errorf("storage: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagBackend, cfgBackend, backendMemory, "Storage backend")

	for _, v := range []string{
		cfgBackend,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
