package epochtime

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cfgBackend        = "epochtime.backend"
	cfgSystemInterval = "epochtime.system.interval"

	backendSystem = "system"
	backendMock   = "mock"
)

var (
	flagBackend        string
	flagSystemInterval int64
)

// New constructs a new TimeSource based on the configuration flags.
func New(cmd *cobra.Command) (TimeSource, error) {
	backend, _ := cmd.Flags().GetString(cfgBackend)
	switch strings.ToLower(backend) {
	case backendSystem:
		interval, _ := cmd.Flags().GetInt64(cfgSystemInterval)
		return NewSystemTimeSource(interval)
	case backendMock:
		return NewMockTimeSource(), nil
	default:
		return nil, fmt.Errorf("epochtime: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagBackend, cfgBackend, backendSystem, "Epoch time backend")
	cmd.Flags().Int64Var(&flagSystemInterval, cfgSystemInterval, EpochInterval, "Epoch interval")

	for _, v := range []string{
		cfgBackend,
		cfgSystemInterval,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) //nolint: errcheck
	}
}
