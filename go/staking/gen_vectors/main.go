// gen_vectors generates test vectors for the staking transactions.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/testvectors"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func main() {
	// Configure chain context for all signatures using chain domain separation.
	var chainContext hash.Hash
	chainContext.FromBytes([]byte("staking test vectors"))
	signature.SetChainContext(chainContext.String())

	var vectors []testvectors.TestVector

	// Generate different gas fees.
	for _, fee := range []*transaction.Fee{
		{},
		{Amount: *quantity.NewFromUint64(100000000), Gas: 1000},
		{Amount: *quantity.NewFromUint64(0), Gas: 1000},
		{Amount: *quantity.NewFromUint64(4242), Gas: 1000},
	} {
		// Generate different nonces.
		for _, nonce := range []uint64{0, 1, 10, 42, 1000, 1_000_000, 10_000_000, math.MaxUint64} {

			// Generate transfer transactions.
			transferDst := memorySigner.NewTestSigner("oasis-core staking test vectors: Transfer dst")
			transferDstAddr := staking.NewAddress(transferDst.Public())
			for _, amt := range []uint64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewTransferTx(nonce, fee, &staking.Transfer{
						To:     transferDstAddr,
						Amount: *quantity.NewFromUint64(amt),
					}),
				} {
					vectors = append(vectors, testvectors.MakeTestVector("Transfer", tx, true))
				}
			}

			// Generate burn transactions.
			for _, amt := range []uint64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewBurnTx(nonce, fee, &staking.Burn{
						Amount: *quantity.NewFromUint64(amt),
					}),
				} {
					vectors = append(vectors, testvectors.MakeTestVector("Burn", tx, true))
				}
			}

			// Generate escrow transactions.
			escrowDst := memorySigner.NewTestSigner("oasis-core staking test vectors: Escrow dst")
			escrowDstAddr := staking.NewAddress(escrowDst.Public())
			for _, amt := range []uint64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewAddEscrowTx(nonce, fee, &staking.Escrow{
						Account: escrowDstAddr,
						Amount:  *quantity.NewFromUint64(amt),
					}),
				} {
					vectors = append(vectors, testvectors.MakeTestVector("Escrow", tx, true))
				}
			}

			// Generate reclaim escrow transactions.
			escrowSrc := memorySigner.NewTestSigner("oasis-core staking test vectors: ReclaimEscrow src")
			escrowSrcAddr := staking.NewAddress(escrowSrc.Public())
			for _, amt := range []uint64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewReclaimEscrowTx(nonce, fee, &staking.ReclaimEscrow{
						Account: escrowSrcAddr,
						Shares:  *quantity.NewFromUint64(amt),
					}),
				} {
					vectors = append(vectors, testvectors.MakeTestVector("ReclaimEscrow", tx, true))
				}
			}

			// Generate amend commission schedule transactions.
			for _, steps := range []int{0, 1, 2, 5} {
				for _, startEpoch := range []uint64{0, 10, 1000, 1_000_000} {
					for _, rate := range []uint64{0, 10, 1000, 10_000, 50_000, 100_000} {
						var cs staking.CommissionSchedule
						for i := 0; i < steps; i++ {
							cs.Rates = append(cs.Rates, staking.CommissionRateStep{
								Start: beacon.EpochTime(startEpoch),
								Rate:  *quantity.NewFromUint64(rate),
							})
							cs.Bounds = append(cs.Bounds, staking.CommissionRateBoundStep{
								Start:   beacon.EpochTime(startEpoch),
								RateMin: *quantity.NewFromUint64(rate),
								RateMax: *quantity.NewFromUint64(rate),
							})
						}

						tx := staking.NewAmendCommissionScheduleTx(nonce, fee, &staking.AmendCommissionSchedule{
							Amendment: cs,
						})
						vectors = append(vectors, testvectors.MakeTestVector("AmendCommissionSchedule", tx, true))
					}
				}
			}

			// Generate allow transactions.
			beneficiary := memorySigner.NewTestSigner("oasis-core staking test vectors: Allow beneficiary")
			beneficiaryAddr := staking.NewAddress(beneficiary.Public())
			for _, amt := range []uint64{0, 1000, 10_000_000} {
				for _, negative := range []bool{false, true} {
					for _, tx := range []*transaction.Transaction{
						staking.NewAllowTx(nonce, fee, &staking.Allow{
							Beneficiary:  beneficiaryAddr,
							Negative:     negative,
							AmountChange: *quantity.NewFromUint64(amt),
						}),
					} {
						vectors = append(vectors, testvectors.MakeTestVector("Withdraw", tx, true))
					}
				}
			}

			// Generate withdraw transactions.
			withdrawSrc := memorySigner.NewTestSigner("oasis-core staking test vectors: Withdraw src")
			withdrawSrcAddr := staking.NewAddress(withdrawSrc.Public())
			for _, amt := range []uint64{0, 1000, 10_000_000} {
				for _, tx := range []*transaction.Transaction{
					staking.NewWithdrawTx(nonce, fee, &staking.Withdraw{
						From:   withdrawSrcAddr,
						Amount: *quantity.NewFromUint64(amt),
					}),
				} {
					vectors = append(vectors, testvectors.MakeTestVector("Withdraw", tx, true))
				}
			}
		}
	}

	// Generate output.
	jsonOut, err := json.MarshalIndent(&vectors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding test vectors: %v\n", err)
	}
	fmt.Printf("%s", jsonOut)
}
