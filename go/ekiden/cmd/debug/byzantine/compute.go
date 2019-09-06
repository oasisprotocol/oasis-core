package byzantine

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
	"github.com/oasislabs/ekiden/go/tendermint/service"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
)

type computeBatchContext struct {
	bd    commitment.TxnSchedulerBatchDispatch
	bdSig signature.Signature

	ioTree    *transaction.Tree
	txs       []*transaction.Transaction
	stateTree *urkel.Tree

	stateWriteLog writelog.WriteLog
	newStateRoot  hash.Hash
	ioWriteLog    writelog.WriteLog
	newIORoot     hash.Hash

	storageReceipts []*storage.Receipt
	commit          *commitment.ComputeCommitment
}

func newComputeBatchContext() *computeBatchContext {
	return &computeBatchContext{}
}

func (cbc *computeBatchContext) receiveBatch(ph *p2pHandle) error {
	req := <-ph.requests
	req.responseCh <- nil

	if req.msg.SignedTxnSchedulerBatchDispatch == nil {
		return errors.Errorf("expecting signed transaction scheduler batch dispatch message, got %+v", req.msg)
	}

	if err := req.msg.SignedTxnSchedulerBatchDispatch.Open(&cbc.bd); err != nil {
		return errors.Wrap(err, "request message SignedTxnSchedulerBatchDispatch Open")
	}

	cbc.bdSig = req.msg.SignedTxnSchedulerBatchDispatch.Signature
	return nil
}

func (cbc *computeBatchContext) openTrees(ctx context.Context, rs syncer.ReadSyncer) error {
	var err error
	cbc.ioTree, err = transaction.NewTree(ctx, rs, storage.Root{
		Namespace: cbc.bd.Header.Namespace,
		Round:     cbc.bd.Header.Round + 1,
		Hash:      cbc.bd.IORoot,
	})
	if err != nil {
		return errors.Wrap(err, "transaction NewTree")
	}

	cbc.txs, err = cbc.ioTree.GetTransactions(ctx)
	if err != nil {
		return errors.Wrap(err, "IO tree GetTransactions")
	}

	cbc.stateTree, err = urkel.NewWithRoot(ctx, rs, nil, storage.Root{
		Namespace: cbc.bd.Header.Namespace,
		Round:     cbc.bd.Header.Round,
		Hash:      cbc.bd.Header.StateRoot,
	})
	if err != nil {
		return errors.Wrap(err, "urkel NewWithRoot")
	}

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
		return errors.Wrap(err, "IO tree AddTransaction")
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
		return errors.Wrap(err, "state tree Commit")
	}

	cbc.ioWriteLog, cbc.newIORoot, err = cbc.ioTree.Commit(ctx)
	if err != nil {
		return errors.Wrap(err, "state tree Commit")
	}

	return nil
}

func (cbc *computeBatchContext) uploadBatch(ctx context.Context, hnss []*honestNodeStorage) error {
	var err error
	cbc.storageReceipts, err = storageBroadcastApplyBatch(ctx, hnss, cbc.bd.Header.Namespace, cbc.bd.Header.Round+1, []storage.ApplyOp{
		storage.ApplyOp{
			SrcRound: cbc.bd.Header.Round + 1,
			SrcRoot:  cbc.bd.IORoot,
			DstRoot:  cbc.newIORoot,
			WriteLog: cbc.ioWriteLog,
		},
		storage.ApplyOp{
			SrcRound: cbc.bd.Header.Round,
			SrcRoot:  cbc.bd.Header.StateRoot,
			DstRoot:  cbc.newStateRoot,
			WriteLog: cbc.stateWriteLog,
		},
	})
	if err != nil {
		return errors.Wrap(err, "storage broadcast apply batch")
	}

	return nil
}

func (cbc *computeBatchContext) createCommitment(id *identity.Identity, committeeID hash.Hash) error {
	var storageSigs []signature.Signature
	for _, receipt := range cbc.storageReceipts {
		storageSigs = append(storageSigs, receipt.Signature)
	}
	var err error
	cbc.commit, err = commitment.SignComputeCommitment(id.NodeSigner, &commitment.ComputeBody{
		CommitteeID: committeeID,
		Header: commitment.ComputeResultsHeader{
			PreviousHash: cbc.bd.Header.EncodedHash(),
			IORoot:       cbc.newIORoot,
			StateRoot:    cbc.newStateRoot,
		},
		StorageSignatures: storageSigs,
		// RakSig not set
		TxnSchedSig:      cbc.bdSig,
		InputRoot:        cbc.bd.IORoot,
		InputStorageSigs: cbc.bd.StorageSignatures,
	})
	if err != nil {
		return errors.Wrap(err, "commitment sign compute commitment")
	}

	return nil
}

func (cbc *computeBatchContext) publishToCommittee(svc service.TendermintService, height int64, committee *scheduler.Committee, role scheduler.Role, ph *p2pHandle, runtimeID signature.PublicKey, groupVersion int64) error {
	if err := schedulerPublishToCommittee(svc, height, committee, role, ph, &p2p.Message{
		RuntimeID:    runtimeID,
		GroupVersion: groupVersion,
		SpanContext:  nil,
		ComputeWorkerFinished: &p2p.ComputeWorkerFinished{
			Commitment: *cbc.commit,
		},
	}); err != nil {
		return errors.Wrap(err, "scheduler publish to committee")
	}

	return nil
}
