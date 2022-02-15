package byzantine

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storageP2P "github.com/oasisprotocol/oasis-core/go/worker/storage/p2p"
)

type byzantine struct {
	logger *logging.Logger

	identity *identity.Identity

	tendermint     *honestTendermint
	p2p            *p2pHandle
	storage        *storageWorker
	storageClients []*storageClient

	runtimeID    common.Namespace
	capabilities *node.Capabilities
	rak          signature.Signer

	electionHeight    int64
	electionEpoch     beacon.EpochTime
	executorCommittee *scheduler.Committee
}

func (b *byzantine) stop() error {
	if err := b.tendermint.stop(); err != nil {
		return fmt.Errorf("tendermint stop failed: %w", err)
	}

	if err := b.p2p.stop(); err != nil {
		return fmt.Errorf("p2p stop failed: %w", err)
	}

	storageBroadcastCleanup(b.storageClients)

	return nil
}

func (b *byzantine) receiveAndScheduleTransactions(ctx context.Context, cbc *computeBatchContext, mode ExecutorMode) (bool, error) {
	// Receive transactions.
	txs := cbc.receiveTransactions(b.p2p, time.Second)
	logger.Debug("executor: received transactions", "transactions", txs)
	// Get latest roothash block.
	var block *block.Block
	block, err := getRoothashLatestBlock(ctx, b.tendermint.service, b.runtimeID)
	if err != nil {
		return false, fmt.Errorf("failed getting latest roothash block: %w", err)
	}

	// Include transactions that nobody else has when configured to do so.
	if viper.GetBool(CfgExecutorProposeBogusTx) {
		logger.Debug("executor scheduler: including bogus transactions")
		txs = append(txs, []byte("this is a bogus transction nr. 1"))
	}

	// Prepare proposal.
	if err = cbc.prepareProposal(ctx, block, txs, b.identity); err != nil {
		panic(fmt.Sprintf("executor proposing batch: %+v", err))
	}

	if mode == ModeExecutorFailureIndicating {
		// Submit failure indicating commitment and stop.
		logger.Debug("executor failure indicating: submitting commitment and stopping")
		if err = cbc.createCommitment(b.identity, nil, commitment.FailureUnknown); err != nil {
			panic(fmt.Sprintf("compute create failure indicating commitment failed: %+v", err))
		}
		if err = cbc.publishToChain(b.tendermint.service, b.identity); err != nil {
			panic(fmt.Sprintf("compute publish to chain failed: %+v", err))
		}
		return false, nil
	}

	// Publish batch.
	cbc.publishProposal(ctx, b.p2p, b.electionEpoch)
	logger.Debug("executor scheduler: dispatched transactions", "transactions", txs)

	// If we're in ModeExecutorWrong, stop after publishing the batch.
	return mode != ModeExecutorWrong, nil
}

func initializeAndRegisterByzantineNode(
	runtimeID common.Namespace,
	nodeRoles node.RolesMask,
	expectedExecutorRole scheduler.Role,
	shouldBeExecutorProposer bool,
	noCommittees bool,
) (*byzantine, error) {
	var err error
	b := &byzantine{
		logger:    logging.GetLogger("cmd/byzantine/node"),
		runtimeID: runtimeID,
	}

	// Initialize.
	if err = cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Setup identity.
	b.identity, err = initDefaultIdentity(cmdCommon.DataDir())
	if err != nil {
		return nil, fmt.Errorf("init default identity failed: %w", err)
	}

	b.logger.Debug("node identity generated",
		"id", b.identity.NodeSigner.Public(),
	)

	// Setup tendermint.
	b.tendermint = newHonestTendermint()
	if err = b.tendermint.start(b.identity, cmdCommon.DataDir()); err != nil {
		return nil, fmt.Errorf("node tendermint start failed: %w", err)
	}

	// Setup P2P.
	b.p2p = newP2PHandle()
	if err = b.p2p.start(b.tendermint, b.identity, b.runtimeID); err != nil {
		return nil, fmt.Errorf("P2P start failed: %w", err)
	}

	// Setup storage.
	storage, err := newStorageNode(b.runtimeID, cmdCommon.DataDir())
	if err != nil {
		return nil, fmt.Errorf("initializing storage node failed: %w", err)
	}
	b.p2p.service.RegisterProtocolServer(storageP2P.NewServer(b.runtimeID, storage))
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
	if err = registryRegisterNode(
		b.tendermint.service,
		b.identity,
		cmdCommon.DataDir(),
		getGrpcAddress(),
		b.p2p.service.Addresses(),
		b.runtimeID,
		b.capabilities,
		nodeRoles,
	); err != nil {
		return nil, fmt.Errorf("registryRegisterNode: %w", err)
	}

	// If we don't care about committees, bail early.
	if noCommittees {
		return b, nil
	}

	committeeStartEpoch := activationEpoch + 1
	b.logger.Debug("waiting for VRF election epoch transition",
		"wait_till", committeeStartEpoch,
	)

	if err = waitForEpoch(b.tendermint.service, committeeStartEpoch); err != nil {
		return nil, fmt.Errorf("waitForEpoch(VRF electionDelay): %w", err)
	}

	b.logger.Debug("getting next election committee",
		"epoch", committeeStartEpoch,
	)

	// Get next election committee.
	b.electionHeight, b.electionEpoch, err = schedulerNextElectionHeight(b.tendermint.service, committeeStartEpoch)
	if err != nil {
		return nil, fmt.Errorf("scheduler next election height failed: %w", err)
	}

	b.logger.Debug("ensuring executor worker role")

	// Ensure we have the expected executor worker role.
	b.executorCommittee, err = schedulerGetCommittee(b.tendermint, b.electionHeight, scheduler.KindComputeExecutor, b.runtimeID)
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
		return nil, fmt.Errorf("not in expected executor transaction scheduler role")
	}
	b.logger.Debug("executor tx scheduler role ok")

	// Connect storage clients to executor committee as we don't store anything locally.
	b.logger.Debug("connecting to storage committee")
	b.storageClients, err = storageConnectToCommittee(b.tendermint, b.electionHeight, b.executorCommittee, scheduler.RoleWorker, b.identity)
	if err != nil {
		return nil, fmt.Errorf("storage connect to committee failed: %w", err)
	}

	return b, nil
}

func waitForEpoch(svc consensus.Backend, epoch beacon.EpochTime) error {
	ch, sub, err := svc.Beacon().WatchEpochs(context.Background())
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		currentEpoch := <-ch
		if currentEpoch >= epoch {
			return nil
		}
	}
}
