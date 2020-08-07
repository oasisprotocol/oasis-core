package byzantine

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

type mergeBatchContext struct {
	currentBlock *block.Block
	commitments  []*commitment.OpenExecutorCommitment

	newBlock *block.Block
	commit   *commitment.MergeCommitment
}

func newMergeBatchContext() *mergeBatchContext {
	return &mergeBatchContext{}
}

func (mbc *mergeBatchContext) loadCurrentBlock(ht *honestTendermint, runtimeID common.Namespace) error {
	var err error
	mbc.currentBlock, err = roothashGetLatestBlock(ht, 0, runtimeID)
	if err != nil {
		return fmt.Errorf("roothash get latest block: %w", err)
	}

	return nil
}

func mergeReceiveCommitment(ph *p2pHandle) (*commitment.OpenExecutorCommitment, error) {
	var req p2pReqRes
	for {
		req = <-ph.requests
		req.responseCh <- nil

		if req.msg.ExecutorCommit == nil {
			continue
		}

		break
	}

	openCom, err := req.msg.ExecutorCommit.Open()
	if err != nil {
		return nil, fmt.Errorf("request message ExecutorWorkerFinished Open: %w", err)
	}

	return openCom, nil
}

func (mbc *mergeBatchContext) receiveCommitments(ph *p2pHandle, count int) error {
	for i := 0; i < count; i++ {
		openCom, err := mergeReceiveCommitment(ph)
		if err != nil {
			return fmt.Errorf("merge receive commitments %d: %w", i, err)
		}
		mbc.commitments = append(mbc.commitments, openCom)
	}

	return nil
}

func (mbc *mergeBatchContext) process(ctx context.Context, hnss []*honestNodeStorage) error {
	collectedCommittees := make(map[hash.Hash]bool)
	var ioRoots, stateRoots []hash.Hash
	for _, commitment := range mbc.commitments {
		if collectedCommittees[commitment.Body.CommitteeID] {
			continue
		}
		collectedCommittees[commitment.Body.CommitteeID] = true
		ioRoots = append(ioRoots, commitment.Body.Header.IORoot)
		stateRoots = append(stateRoots, commitment.Body.Header.StateRoot)
	}

	if len(collectedCommittees) != 1 {
		return fmt.Errorf("multiple committees not supported: %d", len(collectedCommittees))
	}
	signatures := mbc.commitments[0].Body.StorageSignatures
	messages := mbc.commitments[0].Body.Header.Messages

	mbc.newBlock = block.NewEmptyBlock(mbc.currentBlock, 0, block.Normal)
	mbc.newBlock.Header.IORoot = ioRoots[0]
	mbc.newBlock.Header.StateRoot = stateRoots[0]
	mbc.newBlock.Header.Messages = messages
	mbc.newBlock.Header.StorageSignatures = signatures

	return nil
}

func (mbc *mergeBatchContext) createCommitment(id *identity.Identity) error {
	var executorCommits []commitment.ExecutorCommitment
	for _, openCom := range mbc.commitments {
		executorCommits = append(executorCommits, openCom.ExecutorCommitment)
	}
	var err error
	mbc.commit, err = commitment.SignMergeCommitment(id.NodeSigner, &commitment.MergeBody{
		ExecutorCommits: executorCommits,
		Header:          mbc.newBlock.Header,
	})
	if err != nil {
		return fmt.Errorf("commitment sign merge commitment: %w", err)
	}

	return nil
}

func (mbc *mergeBatchContext) publishToChain(svc consensus.Backend, id *identity.Identity, runtimeID common.Namespace) error {
	if err := roothashMergeCommit(svc, id, runtimeID, []commitment.MergeCommitment{*mbc.commit}); err != nil {
		return fmt.Errorf("roothash merge commentment: %w", err)
	}

	return nil
}
