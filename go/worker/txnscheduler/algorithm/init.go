package algorithm

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/worker/txnscheduler/algorithm/api"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler/algorithm/batching"
)

const ()

// New creates a new algorithm.
func New(name string) (api.Algorithm, error) {
	switch name {
	case batching.Name:
		return batching.New()
	default:
		return nil, fmt.Errorf("invalid transaction scheduler algorithm: %s", name)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	for _, v := range []string{} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}

	batching.RegisterFlags(cmd)
}
