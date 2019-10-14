// Package roothash implements the root hash backend.
package roothash

import (
	"context"
	"fmt"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	commonFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/tendermint"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

const (
	cfgRoundTimeout = "roothash.round_timeout"
)

// Flags has the configuration flags.
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

func init() {
	Flags.Duration(cfgRoundTimeout, 10*time.Second, "Root hash round timeout")
	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(tendermint.Flags)
}
