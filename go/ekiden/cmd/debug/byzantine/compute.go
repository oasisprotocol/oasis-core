package byzantine

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/node"
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

type computeBatchContext struct { // nolint: unused
	bd    commitment.TxnSchedulerBatchDispatch
	bdSig signature.Signature

	ioTree    *transaction.Tree
	txs       []*transaction.Transaction
	stateTree *urkel.Tree

	stateWriteLog writelog.WriteLog
	newStateRoot  hash.Hash
	ioWriteLog    writelog.WriteLog
	newIORoot     hash.Hash
}

func newComputeBatchContext() *computeBatchContext { // nolint: deadcode, unused
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

func (cbc *computeBatchContext) addResultSuccess(ctx context.Context, tx *transaction.Transaction, res interface{}, tags transaction.Tags) error { // nolint: unused
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

func (cbc *computeBatchContext) commit(ctx context.Context) error {
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

func (cbc *computeBatchContext) uploadBatch(ctx context.Context, hnss []*honestNodeStorage) ([]*storage.Receipt, error) {
	receipts, err := storageBroadcastApplyBatch(ctx, hnss, cbc.bd.Header.Namespace, cbc.bd.Header.Round+1, []storage.ApplyOp{
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
		return nil, errors.Wrap(err, "storage broadcast apply batch")
	}

	return receipts, nil
}

func (cbc *computeBatchContext) createCommitmentMessage(id *identity.Identity, runtimeID signature.PublicKey, groupVersion int64, committeeID hash.Hash, storageReceipts []*storage.Receipt) (*p2p.Message, error) {
	var storageSigs []signature.Signature
	for _, receipt := range storageReceipts {
		storageSigs = append(storageSigs, receipt.Signature)
	}
	commit, err := commitment.SignComputeCommitment(id.NodeSigner, &commitment.ComputeBody{
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
		return nil, errors.Wrap(err, "commitment sign compute commitment")
	}

	return &p2p.Message{
		RuntimeID:    runtimeID,
		GroupVersion: groupVersion,
		SpanContext:  nil,
		ComputeWorkerFinished: &p2p.ComputeWorkerFinished{
			Commitment: *commit,
		},
	}, nil
}

func computePublishToCommittee(svc service.TendermintService, height int64, committee *scheduler.Committee, role scheduler.Role, ph *p2pHandle, message *p2p.Message) error { // nolint: deadcode, unused
	if err := schedulerForRoleInCommittee(svc, height, committee, role, func(n *node.Node) error {
		ph.service.Publish(ph.context, n, message)

		return nil
	}); err != nil {
		return err
	}

	ph.service.Flush()

	return nil
}
