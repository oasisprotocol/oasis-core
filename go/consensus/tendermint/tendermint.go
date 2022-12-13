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
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/light"
	lightAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/light/api"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

const (
	// CfgMode configures the consensus backend mode.
	CfgMode = "consensus.tendermint.mode"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Mode returns the configured tendermint mode.
func Mode() (mode consensusAPI.Mode, err error) {
	err = mode.UnmarshalText([]byte(viper.GetString(CfgMode)))
	return
}

// New creates a new Tendermint consensus backend.
func New(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	upgrader upgradeAPI.Backend,
	genesisProvider genesisAPI.Provider,
) (consensusAPI.Backend, error) {
	mode, err := Mode()
	if err != nil {
		return nil, err
	}

	switch mode {
	case consensusAPI.ModeFull:
		// Full node.
		return full.New(ctx, dataDir, identity, upgrader, genesisProvider)
	case consensusAPI.ModeArchive:
		// Archive node.
		return full.NewArchive(ctx, dataDir, identity, genesisProvider)
	default:
		return nil, fmt.Errorf("tendermint: unsupported mode: %s", mode)
	}
}

// NewLightClient creates a new Tendermint light client service.
func NewLightClient(ctx context.Context, dataDir string, genesis *genesisAPI.Document, consensus consensusAPI.Backend, p2p rpc.P2P) (lightAPI.ClientService, error) {
	return light.New(ctx, dataDir, genesis, consensus, p2p)
}

func init() {
	Flags.String(CfgMode, consensusAPI.ModeFull.String(), "tendermint mode (full, archive)")

	_ = viper.BindPFlags(Flags)
	Flags.AddFlagSet(common.Flags)
	Flags.AddFlagSet(full.Flags)
}
