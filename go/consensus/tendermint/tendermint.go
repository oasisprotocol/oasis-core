package tendermint

import (
	"context"
	"fmt"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/full"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/seed"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	// CfgMode configures the consensus backend mode.
	CfgMode = "consensus.tendermint.mode"
)

const (
	// ModeFull is the name of the full node consensus mode.
	ModeFull = "full"

	// ModeSeed is the name of the seed-only node consensus mode.
	ModeSeed = "seed"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New creates a new Tendermint consensus backend.
func New(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	upgrader upgradeAPI.Backend,
	genesisProvider genesisAPI.Provider,
) (consensusAPI.Backend, error) {
	switch mode := viper.GetString(CfgMode); mode {
	case ModeFull:
		// Full node.
		return full.New(ctx, dataDir, identity, upgrader, genesisProvider)
	case ModeSeed:
		// Seed-only node.
		return seed.New(dataDir, identity, genesisProvider)
	default:
		return nil, fmt.Errorf("tendermint: unsupported mode: %s", mode)
	}
}

func init() {
	Flags.String(CfgMode, ModeFull, "tendermint mode (full, seed)")

	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(common.Flags)
	Flags.AddFlagSet(full.Flags)
}
