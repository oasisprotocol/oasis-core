package byzantine

import (
	"context"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

type mergeBatchContext struct {
	currentBlock *block.Block
	commitments  []*commitment.OpenComputeCommitment

	storageReceipts []*storage.Receipt
	newBlock        *block.Block
	commit          *commitment.MergeCommitment
}

func newMergeBatchContext() *mergeBatchContext {
	return &mergeBatchContext{}
}

func (mbc *mergeBatchContext) loadCurrentBlock(ht *honestTendermint, runtimeID signature.PublicKey) error {
	var err error
	mbc.currentBlock, err = roothashGetLatestBlock(ht, 0, runtimeID)
	if err != nil {
		return errors.Wrap(err, "roothash get latest block")
	}

	return nil
}

func mergeReceiveCommitment(ph *p2pHandle) (*commitment.OpenComputeCommitment, error) {
	req := <-ph.requests
	req.responseCh <- nil

	if req.msg.ComputeWorkerFinished == nil {
		return nil, errors.Errorf("expecting signed transaction scheduler batch dispatch message, got %+v", req.msg)
	}

	openCom, err := req.msg.ComputeWorkerFinished.Commitment.Open()
	if err != nil {
		return nil, errors.Wrap(err, "request message ComputeWorkerFinished Open")
	}

	return openCom, nil
}

func (mbc *mergeBatchContext) receiveCommitments(ph *p2pHandle, count int) error {
	for i := 0; i < count; i++ {
		openCom, err := mergeReceiveCommitment(ph)
		if err != nil {
			return errors.Wrapf(err, "merge receive commitments %d", i)
		}
		mbc.commitments = append(mbc.commitments, openCom)
	}

	return nil
}

func (mbc *mergeBatchContext) process(ctx context.Context, hnss []*honestNodeStorage) error {
	collectedCommittees := make(map[hash.Hash]bool)
	var ioRoots, stateRoots []hash.Hash
	var messages []*block.Message
	for _, commitment := range mbc.commitments {
		if collectedCommittees[commitment.Body.CommitteeID] {
			continue
		}
		collectedCommittees[commitment.Body.CommitteeID] = true
		ioRoots = append(ioRoots, commitment.Body.Header.IORoot)
		stateRoots = append(stateRoots, commitment.Body.Header.StateRoot)
		if len(commitment.Body.Header.Messages) > 0 {
			messages = append(messages, commitment.Body.Header.Messages...)
		}
	}

	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var err error
	mbc.storageReceipts, err = storageBroadcastMergeBatch(ctx, hnss, mbc.currentBlock.Header.Namespace, mbc.currentBlock.Header.Round, []storage.MergeOp{
		storage.MergeOp{
			Base:   emptyRoot,
			Others: ioRoots,
		},
		storage.MergeOp{
			Base:   mbc.currentBlock.Header.StateRoot,
			Others: stateRoots,
		},
	})
	if err != nil {
		return errors.Wrap(err, "storage broadcast merge batch")
	}

	var firstReceiptBody storage.ReceiptBody
	if err := mbc.storageReceipts[0].Open(&firstReceiptBody); err != nil {
		return errors.Wrap(err, "storage receipt Open")
	}
	var signatures []signature.Signature
	for _, receipt := range mbc.storageReceipts {
		signatures = append(signatures, receipt.Signature)
	}

	mbc.newBlock = block.NewEmptyBlock(mbc.currentBlock, 0, block.Normal)
	mbc.newBlock.Header.IORoot = firstReceiptBody.Roots[0]
	mbc.newBlock.Header.StateRoot = firstReceiptBody.Roots[1]
	mbc.newBlock.Header.Messages = messages
	mbc.newBlock.Header.StorageSignatures = signatures

	return nil
}

func (mbc *mergeBatchContext) createCommitment(id *identity.Identity) error {
	var computeCommits []commitment.ComputeCommitment
	for _, openCom := range mbc.commitments {
		computeCommits = append(computeCommits, openCom.ComputeCommitment)
	}
	var err error
	mbc.commit, err = commitment.SignMergeCommitment(id.NodeSigner, &commitment.MergeBody{
		ComputeCommits: computeCommits,
		Header:         mbc.newBlock.Header,
	})
	if err != nil {
		return errors.Wrap(err, "commitment sign merge commitment")
	}

	return nil
}

func (mbc *mergeBatchContext) publishToChain(svc service.TendermintService, id *identity.Identity, runtimeID signature.PublicKey) error {
	if err := roothashMergeCommit(svc, id, runtimeID, []commitment.MergeCommitment{*mbc.commit}); err != nil {
		return errors.Wrap(err, "roothash merge commentment")
	}

	return nil
}
