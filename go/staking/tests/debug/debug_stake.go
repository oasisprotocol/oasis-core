package debug

import (
	"crypto/rand"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	DebugStateTotalSupply            = *quantity.NewFromUint64(math.MaxInt64)
	DebugStateSrcGeneralBalance      = *quantity.NewFromUint64(math.MaxInt64 - 100)
	DebugStateSrcEscrowActiveBalance = *quantity.NewFromUint64(100)
	DebugStateSrcEscrowActiveShares  = *quantity.NewFromUint64(1000)

	DebugStateSrcSigner   = mustGenerateSigner()
	DebugStateSrcAddress  = api.NewAddress(DebugStateSrcSigner.Public())
	DebugStateDestSigner  = mustGenerateSigner()
	DebugStateDestAddress = api.NewAddress(DebugStateDestSigner.Public())
)

func GenesisState() api.Genesis {
	return api.Genesis{
		Parameters: api.ConsensusParameters{
			DebondingInterval: 1,
			Thresholds: map[api.ThresholdKind]quantity.Quantity{
				api.KindEntity:            *quantity.NewFromUint64(1),
				api.KindNodeValidator:     *quantity.NewFromUint64(2),
				api.KindNodeCompute:       *quantity.NewFromUint64(3),
				api.KindNodeStorage:       *quantity.NewFromUint64(4),
				api.KindNodeKeyManager:    *quantity.NewFromUint64(5),
				api.KindRuntimeCompute:    *quantity.NewFromUint64(6),
				api.KindRuntimeKeyManager: *quantity.NewFromUint64(7),
			},
			Slashing: map[api.SlashReason]api.Slash{
				api.SlashDoubleSigning: {
					Amount:         *quantity.NewFromUint64(math.MaxInt64), // Slash everything.
					FreezeInterval: 1,
				},
			},
			MinDelegationAmount:     *quantity.NewFromUint64(10),
			MaxAllowances:           32,
			FeeSplitWeightVote:      *quantity.NewFromUint64(1),
			RewardFactorEpochSigned: *quantity.NewFromUint64(1),
			// Zero RewardFactorBlockProposed is normal.
		},
		TokenSymbol: "TEST",
		TotalSupply: DebugStateTotalSupply,
		Ledger: map[api.Address]*api.Account{
			DebugStateSrcAddress: {
				General: api.GeneralAccount{
					Balance: DebugStateSrcGeneralBalance,
				},
				Escrow: api.EscrowAccount{
					Active: api.SharePool{
						Balance:     DebugStateSrcEscrowActiveBalance,
						TotalShares: DebugStateSrcEscrowActiveShares,
					},
				},
			},
		},
		Delegations: map[api.Address]map[api.Address]*api.Delegation{
			DebugStateSrcAddress: {
				DebugStateSrcAddress: {
					Shares: DebugStateSrcEscrowActiveShares,
				},
			},
		},
	}
}

func AddressFromString(s string) api.Address {
	var addr api.Address
	if err := addr.UnmarshalText([]byte(s)); err != nil {
		panic(err)
	}
	return addr
}

func mustGenerateSigner() signature.Signer {
	k, err := memorySigner.NewSigner(rand.Reader)
	if err != nil {
		panic(err)
	}

	return k
}
