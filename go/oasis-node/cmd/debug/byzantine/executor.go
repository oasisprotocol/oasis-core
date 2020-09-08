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
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor/api"
)

type computeBatchContext struct {
	bd    commitment.ProposedBatch
	bdSig signature.Signature

	ioTree    *transaction.Tree
	txs       []*transaction.Transaction
	stateTree mkvs.Tree

	stateWriteLog writelog.WriteLog
	newStateRoot  hash.Hash
	ioWriteLog    writelog.WriteLog
	newIORoot     hash.Hash

	storageReceipts []*storage.Receipt
	commit          *commitment.ExecutorCommitment
}

func newComputeBatchContext() *computeBatchContext {
	return &computeBatchContext{}
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

func (cbc *computeBatchContext) proposeTransactionBatch(ctx context.Context, groupVersion int64, hnss []*honestNodeStorage, currentBlock *block.Block, batch []*api.Tx, identity *identity.Identity, p2pH *p2pHandle) error {
	// Generate the initial I/O root containing only the inputs (outputs and
	// tags will be added later by the executor nodes).
	lastHeader := currentBlock.Header
	emptyRoot := storage.Root{
		Namespace: lastHeader.Namespace,
		Version:   lastHeader.Round + 1,
	}
	emptyRoot.Hash.Empty()

	ioTree := transaction.NewTree(nil, emptyRoot)
	defer ioTree.Close()

	for idx, tx := range batch {
		if err := ioTree.AddTransaction(ctx, transaction.Transaction{Input: tx.Data, BatchOrder: uint32(idx)}, nil); err != nil {
			return err
		}
	}

	ioWriteLog, ioRoot, err := ioTree.Commit(ctx)
	if err != nil {
		return err
	}
	ioReceipts, err := storageBroadcastApply(ctx, hnss, &storage.ApplyRequest{
		Namespace: lastHeader.Namespace,
		SrcRound:  lastHeader.Round + 1,
		SrcRoot:   emptyRoot.Hash,
		DstRound:  lastHeader.Round + 1,
		DstRoot:   ioRoot,
		WriteLog:  ioWriteLog,
	})
	if err != nil {
		return err
	}

	ioReceiptSignatures := []signature.Signature{}
	for _, receipt := range ioReceipts {
		ioReceiptSignatures = append(ioReceiptSignatures, receipt.Signature)
	}

	dispatchMsg := &commitment.ProposedBatch{
		IORoot:            ioRoot,
		StorageSignatures: ioReceiptSignatures,
		Header:            currentBlock.Header,
	}
	signedDispatchMsg, err := commitment.SignProposedBatch(identity.NodeSigner, dispatchMsg)
	if err != nil {
		return fmt.Errorf("failed to sign txn scheduler batch: %w", err)
	}

	p2pH.service.Publish(
		ctx,
		defaultRuntimeID,
		&p2p.Message{
			GroupVersion:  groupVersion,
			ProposedBatch: signedDispatchMsg,
		},
	)

	cbc.bd = *dispatchMsg
	cbc.bdSig = signedDispatchMsg.Signature

	return nil
}

func (cbc *computeBatchContext) receiveBatch(ph *p2pHandle) error {
	var req p2pReqRes
	for {
		req = <-ph.requests
		req.responseCh <- nil

		if req.msg.ProposedBatch == nil {
			continue
		}

		break
	}

	if err := req.msg.ProposedBatch.Open(&cbc.bd); err != nil {
		return fmt.Errorf("request message SignedProposedBatchDispatch Open: %w", err)
	}

	cbc.bdSig = req.msg.ProposedBatch.Signature
	return nil
}

func (cbc *computeBatchContext) openTrees(ctx context.Context, rs syncer.ReadSyncer) error {
	var err error
	cbc.ioTree = transaction.NewTree(rs, storage.Root{
		Namespace: cbc.bd.Header.Namespace,
		Version:   cbc.bd.Header.Round + 1,
		Hash:      cbc.bd.IORoot,
	})

	cbc.txs, err = cbc.ioTree.GetTransactions(ctx)
	if err != nil {
		return fmt.Errorf("IO tree GetTransactions: %w", err)
	}

	cbc.stateTree = mkvs.NewWithRoot(rs, nil, storage.Root{
		Namespace: cbc.bd.Header.Namespace,
		Version:   cbc.bd.Header.Round,
		Hash:      cbc.bd.Header.StateRoot,
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
	cbc.stateWriteLog, cbc.newStateRoot, err = cbc.stateTree.Commit(ctx, cbc.bd.Header.Namespace, cbc.bd.Header.Round+1)
	if err != nil {
		return fmt.Errorf("state tree Commit: %w", err)
	}

	cbc.ioWriteLog, cbc.newIORoot, err = cbc.ioTree.Commit(ctx)
	if err != nil {
		return fmt.Errorf("state tree Commit: %w", err)
	}

	return nil
}

func (cbc *computeBatchContext) uploadBatch(ctx context.Context, hnss []*honestNodeStorage) error {
	var err error
	cbc.storageReceipts, err = storageBroadcastApplyBatch(ctx, hnss, cbc.bd.Header.Namespace, cbc.bd.Header.Round+1, []storage.ApplyOp{
		{
			SrcRound: cbc.bd.Header.Round + 1,
			SrcRoot:  cbc.bd.IORoot,
			DstRoot:  cbc.newIORoot,
			WriteLog: cbc.ioWriteLog,
		},
		{
			SrcRound: cbc.bd.Header.Round,
			SrcRoot:  cbc.bd.Header.StateRoot,
			DstRoot:  cbc.newStateRoot,
			WriteLog: cbc.stateWriteLog,
		},
	})
	if err != nil {
		return fmt.Errorf("storage broadcast apply batch: %w", err)
	}

	return nil
}

func (cbc *computeBatchContext) createCommitment(id *identity.Identity, rak signature.Signer, committeeID hash.Hash) error {
	var storageSigs []signature.Signature
	for _, receipt := range cbc.storageReceipts {
		storageSigs = append(storageSigs, receipt.Signature)
	}
	header := commitment.ComputeResultsHeader{
		Round:        cbc.bd.Header.Round + 1,
		PreviousHash: cbc.bd.Header.EncodedHash(),
		IORoot:       cbc.newIORoot,
		StateRoot:    cbc.newStateRoot,
		// TODO: allow script to set roothash messages?
		Messages: []*block.Message{},
	}
	computeBody := &commitment.ComputeBody{
		Header:            header,
		StorageSignatures: storageSigs,
		TxnSchedSig:       cbc.bdSig,
		InputRoot:         cbc.bd.IORoot,
		InputStorageSigs:  cbc.bd.StorageSignatures,
	}
	if rak != nil {
		rakSig, err := signature.Sign(rak, commitment.ComputeResultsHeaderSignatureContext, cbor.Marshal(header))
		if err != nil {
			return fmt.Errorf("signature Sign RAK: %w", err)
		}

		computeBody.RakSig = rakSig.Signature
	}
	var err error
	cbc.commit, err = commitment.SignExecutorCommitment(id.NodeSigner, computeBody)
	if err != nil {
		return fmt.Errorf("commitment sign executor commitment: %w", err)
	}

	return nil
}

func (cbc *computeBatchContext) publishToChain(svc consensus.Backend, id *identity.Identity, runtimeID common.Namespace) error {
	if err := roothashExecutorCommit(svc, id, runtimeID, []commitment.ExecutorCommitment{*cbc.commit}); err != nil {
		return fmt.Errorf("roothash merge commentment: %w", err)
	}

	return nil
}
