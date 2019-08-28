// Package roothash implements the root hash backend.
package roothash

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	commonFlags "github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/tendermint"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	cfgRoundTimeout = "roothash.round_timeout"
)

// Flags has our flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	dataDir string,
	timeSource epochtime.Backend,
	scheduler scheduler.Backend,
	registry registry.Backend,
	beacon beacon.Backend,
	tmService service.TendermintService,
) (api.Backend, error) {
	backend := commonFlags.ConsensusBackend()
	roundTimeout := viper.GetDuration(cfgRoundTimeout)

	var impl api.Backend
	var err error

	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, dataDir, timeSource, beacon, tmService, roundTimeout)
	default:
		return nil, fmt.Errorf("roothash: unsupported backend: '%v'", backend)
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
		cmd.Flags().AddFlagSet(Flags)
	}

	tendermint.RegisterFlags(cmd)
}

func init() {
	Flags.Duration(cfgRoundTimeout, 10*time.Second, "Root hash round timeout")

	_ = viper.BindPFlags(Flags)
}
