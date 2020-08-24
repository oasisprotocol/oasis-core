package commitment

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// ProposedBatchSignatureContext is the context used for signing propose batch
// dispatch messages.
var ProposedBatchSignatureContext = signature.NewContext("oasis-core/roothash: proposed batch", signature.WithChainSeparation())

// ProposedBatch is the message sent from the transaction scheduler
// to executor workers after a batch is ready to be executed.
//
// Don't forget to bump CommitteeProtocol version in go/common/version
// if you change anything in this struct.
type ProposedBatch struct {
	// IORoot is the I/O root containing the inputs (transactions) that
	// the executor node should use.
	IORoot hash.Hash `json:"io_root"`

	// StorageSignatures are the storage receipt signatures for the I/O root.
	StorageSignatures []signature.Signature `json:"storage_signatures"`

	// Header is the block header on which the batch should be based.
	Header block.Header `json:"header"`
}

// SignedProposedBatch is a ProposedBatch, signed by
// the transaction scheduler.
type SignedProposedBatch struct {
	signature.Signed
}

// Open first verifies the blob signature and then unmarshals the blob.
func (s *SignedProposedBatch) Open(tsbd *ProposedBatch) error {
	return s.Signed.Open(ProposedBatchSignatureContext, tsbd)
}

// SignProposedBatch signs a ProposedBatch struct using the
// given signer.
func SignProposedBatch(signer signature.Signer, tsbd *ProposedBatch) (*SignedProposedBatch, error) {
	signed, err := signature.SignSigned(signer, ProposedBatchSignatureContext, tsbd)
	if err != nil {
		return nil, err
	}

	return &SignedProposedBatch{
		Signed: *signed,
	}, nil
}

// GetTransactionScheduler returns the transaction scheduler of the provided
// committee based on the provided round.
func GetTransactionScheduler(committee *scheduler.Committee, round uint64) (*scheduler.CommitteeNode, error) {
	workers := committee.Workers()
	numNodes := uint64(len(workers))
	if numNodes == 0 {
		return nil, fmt.Errorf("GetTransactionScheduler: no workers in commmittee")
	}
	schedulerIdx := round % numNodes
	return workers[schedulerIdx], nil
}
