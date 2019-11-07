// Package roothash implements the root hash backend.
package roothash

import (
	"context"
	"fmt"
	"strings"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/tendermint"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New constructs a new Backend based on the configuration flags.
func New(
	ctx context.Context,
	dataDir string,
	scheduler scheduler.Backend,
	registry registry.Backend,
	beacon beacon.Backend,
	tmService service.TendermintService,
) (api.Backend, error) {
	// XXX: It looks funny to query the Tendermint service to give us the name
	// of the consensus backend, but this will be fixed once issue #1879 is done.
	backend := tmService.GetGenesis().Consensus.Backend

	var impl api.Backend
	var err error

	switch strings.ToLower(backend) {
	case tendermint.BackendName:
		impl, err = tendermint.New(ctx, dataDir, beacon, tmService)
	default:
		return nil, fmt.Errorf("roothash: unsupported backend: '%v'", backend)
	}
	if err != nil {
		return nil, err
	}

	return newMetricsWrapper(impl), nil
}

func init() {
	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(tendermint.Flags)
}
