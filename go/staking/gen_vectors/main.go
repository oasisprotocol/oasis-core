// gen_vectors generates test vectors for the staking transactions.
package main

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func quantityInt64(v int64) quantity.Quantity {
	var q quantity.Quantity
	if err := q.FromInt64(v); err != nil {
		panic(err)
	}
	return q
}

func main() {
	// Configure chain context for all signatures using chain domain separation.
	var chainContext hash.Hash
	chainContext.FromBytes([]byte("staking test vectors"))
	signature.SetChainContext(chainContext.String())

	var vectors []TestVector

	// Generate different gas fees.
	for _, fee := range []*transaction.Fee{
		&transaction.Fee{},
		&transaction.Fee{Amount: quantityInt64(100000000), Gas: 1000},
		&transaction.Fee{Amount: quantityInt64(0), Gas: 1000},
		&transaction.Fee{Amount: quantityInt64(4242), Gas: 1000},
	} {
		// Generate different nonces.
		for _, nonce := range []uint64{0, 1, 10, 42, 1000, 1_000_000, 10_000_000, math.MaxUint64} {
			// Valid transfer transactions.
			transferDst := memorySigner.NewTestSigner("oasis-core staking test vectors: Transfer dst")
			for _, amt := range []int64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewTransferTx(nonce, fee, &staking.Transfer{
						To:     transferDst.Public(),
						Tokens: quantityInt64(amt),
					}),
				} {
					vectors = append(vectors, makeTestVector("Transfer", tx))
				}
			}

			// Valid burn transactions.
			for _, amt := range []int64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewBurnTx(nonce, fee, &staking.Burn{
						Tokens: quantityInt64(amt),
					}),
				} {
					vectors = append(vectors, makeTestVector("Burn", tx))
				}
			}

			// Valid escrow transactions.
			escrowDst := memorySigner.NewTestSigner("oasis-core staking test vectors: Escrow dst")
			for _, amt := range []int64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewAddEscrowTx(nonce, fee, &staking.Escrow{
						Account: escrowDst.Public(),
						Tokens:  quantityInt64(amt),
					}),
				} {
					vectors = append(vectors, makeTestVector("Escrow", tx))
				}
			}

			// Valid reclaim escrow transactions.
			escrowSrc := memorySigner.NewTestSigner("oasis-core staking test vectors: ReclaimEscrow src")
			for _, amt := range []int64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewReclaimEscrowTx(nonce, fee, &staking.ReclaimEscrow{
						Account: escrowSrc.Public(),
						Shares:  quantityInt64(amt),
					}),
				} {
					vectors = append(vectors, makeTestVector("ReclaimEscrow", tx))
				}
			}

			// Valid amend commission schedule transactions.
			for _, steps := range []int{0, 1, 2, 5} {
				for _, startEpoch := range []uint64{0, 10, 1000, 1_000_000} {
					for _, rate := range []int64{0, 10, 1000, 10_000, 50_000, 100_000} {
						var cs staking.CommissionSchedule
						for i := 0; i < steps; i++ {
							cs.Rates = append(cs.Rates, staking.CommissionRateStep{
								Start: epochtime.EpochTime(startEpoch),
								Rate:  quantityInt64(rate),
							})
							cs.Bounds = append(cs.Bounds, staking.CommissionRateBoundStep{
								Start:   epochtime.EpochTime(startEpoch),
								RateMin: quantityInt64(rate),
								RateMax: quantityInt64(rate),
							})
						}

						tx := staking.NewAmendCommissionScheduleTx(nonce, fee, &staking.AmendCommissionSchedule{
							Amendment: cs,
						})
						vectors = append(vectors, makeTestVector("AmendCommissionSchedule", tx))
					}
				}
			}
		}
	}

	// Generate output.
	jsonOut, _ := json.MarshalIndent(&vectors, "", "  ")
	fmt.Printf("%s", jsonOut)
}
