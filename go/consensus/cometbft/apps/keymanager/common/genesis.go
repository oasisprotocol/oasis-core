package common

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// RegistryRuntimes returns verified genesis runtimes.
func RegistryRuntimes(ctx *tmapi.Context, doc *genesis.Document, epoch beacon.EpochTime) map[common.Namespace]*registry.Runtime {
	// TODO: The better thing to do would be to move the registry init
	// before the keymanager, and just query the registry for the runtime
	// list.
	regSt := doc.Registry
	rtMap := make(map[common.Namespace]*registry.Runtime)
	for _, rt := range regSt.Runtimes {
		err := registry.VerifyRuntime(&regSt.Parameters, ctx.Logger(), rt, true, false, epoch, true)
		if err != nil {
			ctx.Logger().Error("InitChain: Invalid runtime",
				"err", err,
			)
			continue
		}

		if rt.Kind == registry.KindKeyManager {
			rtMap[rt.ID] = rt
		}
	}

	return rtMap
}
