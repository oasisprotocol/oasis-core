// gen_vectors generates test vectors for the registry transactions.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/testvectors"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func valideRegisterEntity(v uint16) bool {
	if v < entity.MinDescriptorVersion || v > entity.MaxDescriptorVersion {
		return false
	}
	return true
}

func main() {
	// Configure chain context for all signatures using chain domain separation.
	var chainContext hash.Hash
	chainContext.FromBytes([]byte("registry test vectors"))
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

			// Generate register entity transactions.
			for _, v := range []uint16{entity.LatestDescriptorVersion} {
				for _, numNodes := range []int{0, 1, 2, 5} {
					entitySigner := memorySigner.NewTestSigner("oasis-core registry test vectors: RegisterEntity signer")
					ent := entity.Entity{
						Versioned: cbor.NewVersioned(v),
						ID:        entitySigner.Public(),
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
					valid := valideRegisterEntity(v)
					vectors = append(vectors, testvectors.MakeTestVectorWithSigner("RegisterEntity", tx, valid, entitySigner))
				}
			}

			// Generate deregister entity transactions.
			tx := registry.NewDeregisterEntityTx(nonce, fee)
			vectors = append(vectors, testvectors.MakeTestVector("DeregisterEntity", tx, true))

			// Generate unfreeze node transactions.
			nodeSigner := memorySigner.NewTestSigner("oasis-core registry test vectors: UnfreezeNode signer")
			tx = registry.NewUnfreezeNodeTx(nonce, fee, &registry.UnfreezeNode{
				NodeID: nodeSigner.Public(),
			})
			vectors = append(vectors, testvectors.MakeTestVector("UnfreezeNode", tx, true))
		}
	}

	// Generate output.
	jsonOut, err := json.MarshalIndent(&vectors, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding test vectors: %v\n", err)
	}
	fmt.Printf("%s", jsonOut)
}
