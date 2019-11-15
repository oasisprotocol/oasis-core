package tests

import (
	"crypto/rand"
	"math"
	"math/big"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

var (
	DebugStateTestTotalSupply = QtyFromInt(math.MaxInt64)

	DebugGenesisState = api.Genesis{
		Parameters: api.ConsensusParameters{
			DebondingInterval: 1,
			Thresholds: map[api.ThresholdKind]quantity.Quantity{
				api.KindEntity:    QtyFromInt(1),
				api.KindValidator: QtyFromInt(2),
				api.KindCompute:   QtyFromInt(3),
				api.KindStorage:   QtyFromInt(4),
			},
			AcceptableTransferPeers: map[signature.PublicKey]bool{
				// test runtime 0 from roothash tester
				publicKeyFromHex("612b31ddd66fc99e41cc9996f4029ea84752785d7af329d4595c4bcf8f5e4215"): true,
			},
			Slashing: map[api.SlashReason]api.Slash{
				api.SlashDoubleSigning: api.Slash{
					Amount:         QtyFromInt(math.MaxInt64), // Slash everything.
					FreezeInterval: 1,
				},
			},
			MinDelegationAmount: QtyFromInt(10),
		},
		TotalSupply: DebugStateTestTotalSupply,
		Ledger: map[signature.PublicKey]*api.Account{
			DebugStateSrcID: &api.Account{
				General: api.GeneralAccount{
					Balance: DebugStateTestTotalSupply,
				},
			},
		},
	}

	DebugStateSrcSigner = mustGenerateSigner()
	DebugStateSrcID     = DebugStateSrcSigner.Public()
	destSigner          = mustGenerateSigner()
	DebugStateDestID    = destSigner.Public()
)

func QtyFromInt(n int) quantity.Quantity {
	q := quantity.NewQuantity()
	if err := q.FromBigInt(big.NewInt(int64(n))); err != nil {
		panic(err)
	}
	return *q
}

func mustGenerateSigner() signature.Signer {
	k, err := memorySigner.NewSigner(rand.Reader)
	if err != nil {
		panic(err)
	}

	return k
}

func publicKeyFromHex(s string) signature.PublicKey {
	var pk signature.PublicKey
	if err := pk.UnmarshalHex(s); err != nil {
		panic(err)
	}
	return pk
}
