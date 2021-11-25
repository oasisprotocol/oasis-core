package byzantine

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor/api"
)

type computeBatchContext struct {
	runtimeID common.Namespace

	proposal       *commitment.Proposal
	proposalHeader *commitment.ProposalHeader

	txs       []*transaction.Transaction
	ioTree    *transaction.Tree
	stateTree mkvs.Tree

	stateWriteLog writelog.WriteLog
	newStateRoot  hash.Hash
	ioWriteLog    writelog.WriteLog
	newIORoot     hash.Hash

	commit *commitment.ExecutorCommitment
}

func newComputeBatchContext(runtimeID common.Namespace) *computeBatchContext {
	return &computeBatchContext{
		runtimeID: runtimeID,
	}
}

func (cbc *computeBatchContext) receiveTransactions(ph *p2pHandle, timeout time.Duration) []*api.Tx {
	var req p2pReqRes
	txs := []*api.Tx{}
	existing := make(map[hash.Hash]bool)

ReceiveTransactions:
	for {
		select {
		case req = <-ph.requests:
			req.responseCh <- nil
			if req.msg.Tx == nil {
				continue
			}
			txHash := hash.NewFromBytes(req.msg.Tx.Data)
			if existing[txHash] {
				continue
			}

			txs = append(txs, req.msg.Tx)
			existing[txHash] = true
		case <-time.After(timeout):
			break ReceiveTransactions
		}
	}

	return txs
}

func (cbc *computeBatchContext) publishProposal(
	ctx context.Context,
	p2pH *p2pHandle,
	groupVersion int64,
) {
	if cbc.proposal == nil {
		panic("no prepared proposal")
	}

	p2pH.service.Publish(
		ctx,
		cbc.runtimeID,
		&p2p.Message{
			GroupVersion: groupVersion,
			Proposal:     cbc.proposal,
		},
	)
}

func (cbc *computeBatchContext) prepareProposal(
	ctx context.Context,
	currentBlock *block.Block,
	batch []*api.Tx,
	identity *identity.Identity,
) error {
	// Generate the initial I/O root containing only the inputs (outputs and
	// tags will be added later by the executor nodes).
	lastHeader := currentBlock.Header
	emptyRoot := storage.Root{
		Namespace: lastHeader.Namespace,
		Version:   lastHeader.Round + 1,
		Type:      storage.RootTypeIO,
	}
	emptyRoot.Hash.Empty()

	ioTree := transaction.NewTree(nil, emptyRoot)
	defer ioTree.Close()

	var (
		txs      []*transaction.Transaction
		txHashes []hash.Hash
	)
	for idx, rawTx := range batch {
		tx := transaction.Transaction{
			Input:      rawTx.Data,
			BatchOrder: uint32(idx),
		}
		if err := ioTree.AddTransaction(ctx, tx, nil); err != nil {
			return err
		}
		txHashes = append(txHashes, hash.NewFromBytes(rawTx.Data))
		txs = append(txs, &tx)
	}

	_, ioRoot, err := ioTree.Commit(ctx)
	if err != nil {
		return err
	}

	// NOTE: The Byzantine node does not apply to local storage.

	proposalHeader := &commitment.ProposalHeader{
		Round:        lastHeader.Round + 1,
		PreviousHash: lastHeader.EncodedHash(),
		BatchHash:    ioRoot,
	}
	signedProposalHeader, err := proposalHeader.Sign(identity.NodeSigner, lastHeader.Namespace)
	if err != nil {
		return fmt.Errorf("failed to sign proposal header: %w", err)
	}

	proposal := &commitment.Proposal{
		SignedProposalHeader: *signedProposalHeader,
		Batch:                txHashes,
	}

	cbc.proposal = proposal
	cbc.proposalHeader = proposalHeader
	cbc.txs = txs

	return nil
}

func (cbc *computeBatchContext) receiveProposal(ph *p2pHandle) error {
	var proposal *commitment.Proposal
	existing := make(map[hash.Hash]*api.Tx)
	missing := make(map[hash.Hash]bool)

ReceiveProposal:
	for {
		req := <-ph.requests
		req.responseCh <- nil

		switch {
		case req.msg.Tx != nil:
			// Transaction.
			txHash := hash.NewFromBytes(req.msg.Tx.Data)
			if existing[txHash] != nil {
				continue
			}
			existing[txHash] = req.msg.Tx
			delete(missing, txHash)

			// If we have the proposal and all transactions, stop.
			if proposal != nil && len(missing) == 0 {
				break ReceiveProposal
			}
		case req.msg.Proposal != nil:
			// Proposal.
			if proposal != nil {
				return fmt.Errorf("received multiple proposals while only expecting one")
			}
			proposal = req.msg.Proposal

			// Check if any transactions are missing.
			for _, txHash := range proposal.Batch {
				if existing[txHash] != nil {
					continue
				}
				missing[txHash] = true
			}

			// If we have all transactions, continue.
			if len(missing) == 0 {
				break ReceiveProposal
			}
			// TODO: Actually request transactions from peers.
		}
	}

	var proposalHeader commitment.ProposalHeader
	if err := proposal.SignedProposalHeader.Open(cbc.runtimeID, &proposalHeader); err != nil {
		return fmt.Errorf("failed to open received SignedProposalHeader: %w", err)
	}

	cbc.proposal = proposal
	cbc.proposalHeader = &proposalHeader

	cbc.txs = nil
	for idx, txHash := range proposal.Batch {
		cbc.txs = append(cbc.txs, &transaction.Transaction{
			Input:      existing[txHash].Data,
			BatchOrder: uint32(idx),
		})
	}

	return nil
}

func (cbc *computeBatchContext) openTrees(ctx context.Context, blk *block.Block, rs syncer.ReadSyncer) error {
	cbc.ioTree = transaction.NewTree(nil, storage.Root{
		Namespace: cbc.runtimeID,
		Version:   cbc.proposalHeader.Round,
		Type:      storage.RootTypeIO,
		Hash:      cbc.proposalHeader.BatchHash,
	})

	// Add all transactions to the I/O tree.
	for _, tx := range cbc.txs {
		if err := cbc.ioTree.AddTransaction(ctx, *tx, nil); err != nil {
			return fmt.Errorf("failed to add transaction to I/O tree: %w", err)
		}
	}

	// NOTE: We use a remote state tree so the Byzantine node doesn't need to maintain state. This
	//       requires storage nodes with the public storage RPC exposed.
	cbc.stateTree = mkvs.NewWithRoot(rs, nil, storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round,
		Type:      storage.RootTypeState,
		Hash:      blk.Header.StateRoot,
	})

	return nil
}

func (cbc *computeBatchContext) closeTrees() {
	cbc.ioTree.Close()
	cbc.stateTree.Close()
}

func (cbc *computeBatchContext) addResult(ctx context.Context, tx *transaction.Transaction, output []byte, tags transaction.Tags) error {
	txCopy := *tx
	txCopy.Output = output

	// This rewrites the input artifact, but it shouldn't affect the root hash.
	if err := cbc.ioTree.AddTransaction(ctx, txCopy, tags); err != nil {
		return fmt.Errorf("IO tree AddTransaction: %w", err)
	}

	return nil
}

func (cbc *computeBatchContext) addResultSuccess(ctx context.Context, tx *transaction.Transaction, res interface{}, tags transaction.Tags) error {
	// Hack: The actual TxnOutput struct doesn't serialize right.
	return cbc.addResult(ctx, tx, cbor.Marshal(struct {
		Success interface{}
	}{
		Success: res,
	}), tags)
}

func (cbc *computeBatchContext) addResultError(ctx context.Context, tx *transaction.Transaction, err string, tags transaction.Tags) error { // nolint: unused
	// Hack: The actual TxnOutput struct doesn't serialize right.
	return cbc.addResult(ctx, tx, cbor.Marshal(struct {
		Error *string
	}{
		Error: &err,
	}), tags)
}

func (cbc *computeBatchContext) commitTrees(ctx context.Context) error {
	var err error
	cbc.stateWriteLog, cbc.newStateRoot, err = cbc.stateTree.Commit(ctx, cbc.runtimeID, cbc.proposalHeader.Round)
	if err != nil {
		return fmt.Errorf("state tree Commit: %w", err)
	}

	cbc.ioWriteLog, cbc.newIORoot, err = cbc.ioTree.Commit(ctx)
	if err != nil {
		return fmt.Errorf("state tree Commit: %w", err)
	}

	return nil
}

func (cbc *computeBatchContext) createCommitment(
	id *identity.Identity,
	rak signature.Signer,
	failure commitment.ExecutorCommitmentFailure,
) error {
	// TODO: allow script to set roothash messages?
	msgsHash := message.MessagesHash(nil)
	header := commitment.ComputeResultsHeader{
		Round:        cbc.proposalHeader.Round,
		PreviousHash: cbc.proposalHeader.PreviousHash,
		IORoot:       &cbc.newIORoot,
		StateRoot:    &cbc.newStateRoot,
		MessagesHash: &msgsHash,
	}
	ec := &commitment.ExecutorCommitment{
		NodeID: id.NodeSigner.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: header,
		},
	}
	if rak != nil {
		rakSig, err := signature.Sign(rak, commitment.ComputeResultsHeaderSignatureContext, cbor.Marshal(header))
		if err != nil {
			return fmt.Errorf("signature Sign RAK: %w", err)
		}

		ec.Header.RAKSignature = &rakSig.Signature
	}

	if failure != commitment.FailureNone {
		ec.Header.SetFailure(failure)
	}

	err := ec.Sign(id.NodeSigner, cbc.runtimeID)
	if err != nil {
		return fmt.Errorf("commitment sign executor commitment: %w", err)
	}
	cbc.commit = ec

	return nil
}

func (cbc *computeBatchContext) publishToChain(svc consensus.Backend, id *identity.Identity) error {
	if err := roothashExecutorCommit(svc, id, cbc.runtimeID, []commitment.ExecutorCommitment{*cbc.commit}); err != nil {
		return fmt.Errorf("roothash merge commitment: %w", err)
	}

	return nil
}
