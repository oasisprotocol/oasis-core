// gen_vectors generates test vectors for the registry transactions.
package main

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/testvectors"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func main() {
	// Configure chain context for all signatures using chain domain separation.
	var chainContext hash.Hash
	chainContext.FromBytes([]byte("registry test vectors"))
	signature.SetChainContext(chainContext.String())

	var vectors []testvectors.TestVector

	// Generate different gas fees.
	for _, fee := range []*transaction.Fee{
		&transaction.Fee{},
		&transaction.Fee{Amount: *quantity.NewFromUint64(100000000), Gas: 1000},
		&transaction.Fee{Amount: *quantity.NewFromUint64(0), Gas: 1000},
		&transaction.Fee{Amount: *quantity.NewFromUint64(4242), Gas: 1000},
	} {
		// Generate different nonces.
		for _, nonce := range []uint64{0, 1, 10, 42, 1000, 1_000_000, 10_000_000, math.MaxUint64} {
			// Valid register entity transactions.
			entitySigner := memorySigner.NewTestSigner("oasis-core registry test vectors: RegisterEntity signer")
			for _, numNodes := range []int{0, 1, 2, 5} {
				ent := entity.Entity{
					DescriptorVersion: entity.LatestEntityDescriptorVersion,
					ID:                entitySigner.Public(),
				}
				for i := 0; i < numNodes; i++ {
					nodeSigner := memorySigner.NewTestSigner(fmt.Sprintf("oasis core registry test vectors: node signer %d", i))
					ent.Nodes = append(ent.Nodes, nodeSigner.Public())
				}
				sigEnt, err := entity.SignEntity(entitySigner, registry.RegisterEntitySignatureContext, &ent)
				if err != nil {
					panic(err)
				}
				tx := registry.NewRegisterEntityTx(nonce, fee, sigEnt)
				vectors = append(vectors, testvectors.MakeTestVectorWithSigner("RegisterEntity", tx, entitySigner))
			}

			// Valid unfreeze node transactions.
			nodeSigner := memorySigner.NewTestSigner("oasis-core registry test vectors: UnfreezeNode signer")
			tx := registry.NewUnfreezeNodeTx(nonce, fee, &registry.UnfreezeNode{
				NodeID: nodeSigner.Public(),
			})
			vectors = append(vectors, testvectors.MakeTestVector("UnfreezeNode", tx))
		}
	}

	// Generate output.
	jsonOut, _ := json.MarshalIndent(&vectors, "", "  ")
	fmt.Printf("%s", jsonOut)
}
