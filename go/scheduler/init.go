// Package scheduler implements the scheduler backend.
package scheduler

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/scheduler/tendermint"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// New constructs a new Backend based on the configuration flags.
func New(ctx context.Context, timeSource epochtime.Backend, reg registry.Backend, beacon beacon.Backend, service service.TendermintService) (api.Backend, error) {
	backend := commonFlags.ConsensusBackend()
	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		return tendermint.New(ctx, timeSource, service)
	default:
		return nil, fmt.Errorf("scheduler: unsupported backend: '%v'", backend)
	}
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
}
