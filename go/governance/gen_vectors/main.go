// gen_vectors generates test vectors for the governance transactions.
package main

import (
	"encoding/json"
	"fmt"
	"math"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/testvectors"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func main() {
	// Configure chain context for all signatures using chain domain separation.
	var chainContext hash.Hash
	chainContext.FromBytes([]byte("governance test vectors"))
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
			// Valid submit upgrade proposal transaction.
			for _, v := range []uint16{0, api.LatestDescriptorVersion} {
				for _, epoch := range []uint64{0, 1000, 10_000_000} {
					for _, handler := range []string{"", "descriptor-handler"} {
						for _, version := range []version.ProtocolVersions{
							{},
							{ConsensusProtocol: version.Version{Major: 1, Minor: 2, Patch: 3}},
							{
								ConsensusProtocol: version.Version{
									Major: 0,
									Minor: 12,
									Patch: 1,
								},
								RuntimeCommitteeProtocol: version.Version{
									Major: 42,
									Minor: 0,
									Patch: 1,
								},
								RuntimeHostProtocol: version.Version{
									Major: 1,
									Minor: 2,
									Patch: 3,
								},
							},
							version.Versions,
						} {
							for _, tx := range []*transaction.Transaction{
								governance.NewSubmitProposalTx(nonce, fee, &governance.ProposalContent{
									Upgrade: &governance.UpgradeProposal{
										Descriptor: api.Descriptor{
											Versioned: cbor.NewVersioned(v),
											Handler:   handler,
											Target:    version,
											Epoch:     beacon.EpochTime(epoch),
										},
									},
								}),
							} {
								vectors = append(vectors, testvectors.MakeTestVector("SubmitProposal", tx))
							}
						}
					}
				}
			}

			// Valid submit cancel upgrade proposal transaction.
			for _, id := range []uint64{0, 1000, 10_000_000, math.MaxUint64} {
				for _, tx := range []*transaction.Transaction{
					governance.NewSubmitProposalTx(nonce, fee, &governance.ProposalContent{
						CancelUpgrade: &governance.CancelUpgradeProposal{
							ProposalID: id,
						},
					}),
				} {
					vectors = append(vectors, testvectors.MakeTestVector("SubmitProposal", tx))
				}
			}

			// Valid cast vote transactions.
			for _, id := range []uint64{0, 1000, 10_000_000, math.MaxUint64} {
				for _, vote := range []governance.Vote{governance.VoteAbstain, governance.VoteYes, governance.VoteNo} {
					for _, tx := range []*transaction.Transaction{
						governance.NewCastVoteTx(nonce, fee, &governance.ProposalVote{
							ID:   id,
							Vote: vote,
						}),
					} {
						vectors = append(vectors, testvectors.MakeTestVector("SubmitProposal", tx))
					}
				}
			}
		}
	}

	// Generate output.
	jsonOut, _ := json.MarshalIndent(&vectors, "", "  ")
	fmt.Printf("%s", jsonOut)
}
