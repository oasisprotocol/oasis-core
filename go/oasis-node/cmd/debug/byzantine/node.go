package byzantine

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
)

type byzantine struct {
	logger *logging.Logger

	identity *identity.Identity

	tendermint     *honestTendermint
	p2p            *p2pHandle
	storage        *storageWorker
	storageClients []*storageClient
	gRPC           *externalGrpc

	capabilities *node.Capabilities
	rak          signature.Signer

	electionHeight    int64
	executorCommittee *scheduler.Committee
}

func (b *byzantine) stop() error {
	if err := b.tendermint.stop(); err != nil {
		return fmt.Errorf("tendermint stop failed: %w", err)
	}

	if err := b.p2p.stop(); err != nil {
		return fmt.Errorf("p2p stop failed: %w", err)
	}

	b.gRPC.stop()

	storageBroadcastCleanup(b.storageClients)

	return nil
}

func (b *byzantine) receiveAndScheduleTransactions(ctx context.Context, cbc *computeBatchContext, mode ExecutorMode) (bool, error) {
	// Receive transactions.
	txs := cbc.receiveTransactions(b.p2p, time.Second)
	logger.Debug("executor: received transactions", "transactions", txs)
	// Get latest roothash block.
	var block *block.Block
	block, err := getRoothashLatestBlock(ctx, b.tendermint.service, defaultRuntimeID)
	if err != nil {
		return false, fmt.Errorf("failed getting latest roothash block: %w", err)
	}

	// Prepare transaction batch.
	var proposedBatch *commitment.SignedProposedBatch
	proposedBatch, err = cbc.prepareTransactionBatch(ctx, b.storageClients, block, txs, b.identity, mode == ModeExecutorWrong)
	if err != nil {
		panic(fmt.Sprintf("executor proposing batch: %+v", err))
	}

	if mode == ModeExecutorFailureIndicating {
		// Submit failure indicating commitment and stop.
		logger.Debug("executor failure indicating: submitting commitment and stopping")
		if err = cbc.createCommitment(b.identity, nil, b.executorCommittee.EncodedMembersHash(), commitment.FailureStorageUnavailable); err != nil {
			panic(fmt.Sprintf("compute create failure indicating commitment failed: %+v", err))
		}
		if err = cbc.publishToChain(b.tendermint.service, b.identity, defaultRuntimeID); err != nil {
			panic(fmt.Sprintf("compute publish to chain failed: %+v", err))
		}
		return false, nil
	}

	// Publish batch.
	cbc.publishTransactionBatch(ctx, b.p2p, b.electionHeight, proposedBatch)
	logger.Debug("executor scheduler: dispatched transactions", "transactions", txs)

	// If we're in ModeExecutorWrong, stop after publishing the batch.
	return mode != ModeExecutorWrong, nil
}

func initializeAndRegisterByzantineNode(
	nodeRoles node.RolesMask,
	expectedStorageRole scheduler.Role,
	expectedExecutorRole scheduler.Role,
	shouldBeExecutorProposer bool,
	noCommittees bool,
) (*byzantine, error) {
	var err error
	b := &byzantine{
		logger: logging.GetLogger("cmd/byzantine/node"),
	}

	// Initialize.
	if err = common.Init(); err != nil {
		common.EarlyLogAndExit(err)
	}

	// Setup identity.
	b.identity, err = initDefaultIdentity(common.DataDir())
	if err != nil {
		return nil, fmt.Errorf("init default identity failed: %w", err)
	}

	// Setup tendermint.
	b.tendermint = newHonestTendermint()
	if err = b.tendermint.start(b.identity, common.DataDir()); err != nil {
		return nil, fmt.Errorf("node tendermint start failed: %w", err)
	}

	// Setup P2P.
	b.p2p = newP2PHandle()
	if err = b.p2p.start(b.tendermint, b.identity, defaultRuntimeID); err != nil {
		return nil, fmt.Errorf("P2P start failed: %w", err)
	}

	// Setup gRPC.
	b.gRPC, err = newExternalGrpc(b.identity)
	if err != nil {
		return nil, fmt.Errorf("initializing grpc server failed: %w", err)
	}

	// Setup storage.
	storage, err := newStorageNode(b.identity, defaultRuntimeID, common.DataDir())
	if err != nil {
		return nil, fmt.Errorf("initializing storage node failed: %w", err)
	}
	storageAPI.RegisterService(b.gRPC.grpc.Server(), storage)
	if err = b.gRPC.start(); err != nil {
		return nil, fmt.Errorf("starting grpc server failed: %w", err)
	}
	b.storage = storage

	// Wait for activation epoch.
	activationEpoch := beacon.EpochTime(viper.GetUint64(CfgActivationEpoch))
	if err = waitForEpoch(b.tendermint.service, activationEpoch); err != nil {
		return nil, fmt.Errorf("waitForEpoch: %w", err)
	}

	// Register node.
	if viper.GetBool(CfgFakeSGX) {
		if b.rak, b.capabilities, err = initFakeCapabilitiesSGX(); err != nil {
			return nil, fmt.Errorf("initFakeCapabilitiesSGX: %w", err)
		}
	}
	if err = registryRegisterNode(b.tendermint.service, b.identity, common.DataDir(), getGrpcAddress(), b.p2p.service.Addresses(), defaultRuntimeID, b.capabilities, nodeRoles); err != nil {
		return nil, fmt.Errorf("registryRegisterNode: %w", err)
	}

	// If we don't care about committees, bail early.
	if noCommittees {
		return b, nil
	}

	// Get next election committee.
	b.electionHeight, err = schedulerNextElectionHeight(b.tendermint.service, activationEpoch+1)
	if err != nil {
		return nil, fmt.Errorf("scheduler next election height failed: %w", err)
	}

	// Ensure we have the expected executor worker role.
	b.executorCommittee, err = schedulerGetCommittee(b.tendermint, b.electionHeight, scheduler.KindComputeExecutor, defaultRuntimeID)
	if err != nil {
		return nil, fmt.Errorf("scheduler get committee %s at height %d failed: %w", scheduler.KindComputeExecutor, b.electionHeight, err)
	}

	if err = schedulerCheckScheduled(b.executorCommittee, b.identity.NodeSigner.Public(), expectedExecutorRole); err != nil {
		return nil, fmt.Errorf("scheduler check scheduled failed: %w", err)
	}
	b.logger.Debug("executor schedule ok")

	// Ensure we have the expected executor transaction scheduler role.
	isTxScheduler := schedulerCheckTxScheduler(b.executorCommittee, b.identity.NodeSigner.Public(), 0)
	if shouldBeExecutorProposer != isTxScheduler {
		return nil, fmt.Errorf("not expected executor scheduler role. expected: 'is_scheduler=%v'", viper.GetBool(CfgSchedulerRoleExpected))
	}
	b.logger.Debug("executor tx scheduler role ok")

	// Ensure we have the expected storage worker role.
	storageCommittee, err := schedulerGetCommittee(b.tendermint, b.electionHeight, scheduler.KindStorage, defaultRuntimeID)
	if err != nil {
		return nil, fmt.Errorf("scheduler get committee %s failed: %+v", scheduler.KindStorage, err)
	}
	if err = schedulerCheckScheduled(storageCommittee, b.identity.NodeSigner.Public(), expectedStorageRole); err != nil {
		return nil, fmt.Errorf("scheduler check scheduled failed: %w", err)
	}
	b.logger.Debug("executor schedule ok")

	// Connect to storage committee.
	b.logger.Debug("connecting to storage committee")
	b.storageClients, err = storageConnectToCommittee(b.tendermint, b.electionHeight, storageCommittee, scheduler.RoleWorker, b.identity)
	if err != nil {
		return nil, fmt.Errorf("storage connect to committee failed: %w", err)
	}

	return b, nil
}

func waitForEpoch(svc consensus.Backend, epoch beacon.EpochTime) error {
	ch, sub := svc.Beacon().WatchEpochs()
	defer sub.Close()

	for {
		currentEpoch := <-ch
		if currentEpoch >= epoch {
			return nil
		}
	}
}
