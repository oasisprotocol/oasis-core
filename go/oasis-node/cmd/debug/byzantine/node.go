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
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/file"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/client"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/checkpointsync"
)

type byzantine struct {
	logger *logging.Logger

	chainContext string

	identity *identity.Identity

	cometbft      *honestCometBFT
	p2p           *p2pHandle
	storage       *storageWorker
	storageClient storage.Backend

	runtimeID    common.Namespace
	capabilities *node.Capabilities
	rak          signature.Signer

	electionHeight    int64
	electionEpoch     beacon.EpochTime
	executorCommittee *scheduler.Committee
}

func (b *byzantine) stop() error {
	if err := b.cometbft.stop(); err != nil {
		return fmt.Errorf("cometbft stop failed: %w", err)
	}

	if err := b.p2p.stop(); err != nil {
		return fmt.Errorf("p2p stop failed: %w", err)
	}

	return nil
}

func (b *byzantine) receiveAndScheduleTransactions(ctx context.Context, cbc *computeBatchContext, block *block.Block, mode ExecutorMode) (bool, error) {
	// Receive transactions.
	txs := cbc.receiveTransactions(b.p2p, time.Second)
	logger.Debug("executor: received transactions", "transactions", txs)

	// Include transactions that nobody else has when configured to do so.
	if viper.GetBool(CfgExecutorProposeBogusTx) {
		logger.Debug("executor scheduler: including bogus transactions")
		txs = append(txs, []byte("this is a bogus transition nr. 1"))
	}

	// Prepare proposal.
	if err := cbc.prepareProposal(ctx, block, txs, b.identity); err != nil {
		panic(fmt.Sprintf("executor proposing batch: %+v", err))
	}

	if mode == ModeExecutorFailureIndicating {
		// Submit failure indicating commitment and stop.
		logger.Debug("executor failure indicating: submitting commitment and stopping")
		schedulerID := b.identity.NodeSigner.Public()
		if err := cbc.createCommitment(b.identity, schedulerID, nil, commitment.FailureUnknown); err != nil {
			panic(fmt.Sprintf("compute create failure indicating commitment failed: %+v", err))
		}
		if err := cbc.publishToChain(b.cometbft.service, b.identity); err != nil {
			panic(fmt.Sprintf("compute publish to chain failed: %+v", err))
		}
		return false, nil
	}

	// Publish batch.
	cbc.publishProposal(ctx, b.p2p, b.electionEpoch)
	logger.Debug("executor scheduler: dispatched transactions", "transactions", txs)

	// If we're in ModeExecutorRunaway, stop after publishing the batch.
	return mode != ModeExecutorRunaway, nil
}

func initializeAndRegisterByzantineNode(
	runtimeID common.Namespace,
	nodeRoles node.RolesMask,
	expectedExecutorRole scheduler.Role,
	shouldBePrimaryScheduler bool,
	noCommittees bool,
	round uint64,
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

	// Initialize the genesis provider.
	genesis := genesis.NewProvider(cmdFlags.GenesisFile())

	// Retrieve the genesis document and use it to configure the ChainID for
	// signature domain separation. We do this as early as possible.
	genesisDoc, err := genesis.GetGenesisDocument()
	if err != nil {
		return nil, err
	}
	genesisDoc.SetChainContext()

	b.chainContext = genesisDoc.ChainContext()

	// Setup CometBFT.
	b.cometbft = newHonestCometBFT(genesis, genesisDoc)
	if err = b.cometbft.start(b.identity, cmdCommon.DataDir()); err != nil {
		return nil, fmt.Errorf("node cometbft start failed: %w", err)
	}

	// Setup P2P.
	b.p2p = newP2PHandle()
	if err = b.p2p.start(b.cometbft, b.identity, b.chainContext, b.runtimeID); err != nil {
		return nil, fmt.Errorf("P2P start failed: %w", err)
	}

	// Setup storage.
	storage, err := newStorageNode(b.runtimeID, cmdCommon.DataDir())
	if err != nil {
		return nil, fmt.Errorf("initializing storage node failed: %w", err)
	}
	b.p2p.service.RegisterProtocolServer(checkpointsync.NewServer(b.chainContext, b.runtimeID, storage))
	b.storage = storage

	// Wait for activation epoch.
	activationEpoch := beacon.EpochTime(viper.GetUint64(CfgActivationEpoch))
	if err = waitForEpoch(b.cometbft.service, activationEpoch); err != nil {
		return nil, fmt.Errorf("waitForEpoch: %w", err)
	}

	// Register node.
	if viper.GetBool(CfgFakeSGX) {
		if b.rak, b.capabilities, err = initFakeCapabilitiesSGX(b.identity.NodeSigner.Public()); err != nil {
			return nil, fmt.Errorf("initFakeCapabilitiesSGX: %w", err)
		}
	}
	if err = registryRegisterNode(
		b.cometbft.service,
		b.identity,
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

	if err = waitForEpoch(b.cometbft.service, committeeStartEpoch); err != nil {
		return nil, fmt.Errorf("waitForEpoch(VRF electionDelay): %w", err)
	}

	b.logger.Debug("getting next election committee",
		"epoch", committeeStartEpoch,
	)

	// Get next election committee.
	b.electionHeight, b.electionEpoch, err = schedulerNextElectionHeight(b.cometbft.service, committeeStartEpoch)
	if err != nil {
		return nil, fmt.Errorf("scheduler next election height failed: %w", err)
	}

	b.executorCommittee, err = schedulerGetCommittee(b.cometbft, b.electionHeight, scheduler.KindComputeExecutor, b.runtimeID)
	if err != nil {
		return nil, fmt.Errorf("scheduler get committee %s at height %d failed: %w", scheduler.KindComputeExecutor, b.electionHeight, err)
	}

	// Ensure we have the expected executor worker role.
	b.logger.Debug("ensuring executor worker role")
	if err = schedulerCheckScheduled(b.executorCommittee, b.identity.NodeSigner.Public(), expectedExecutorRole); err != nil {
		return nil, fmt.Errorf("scheduler check scheduled failed: %w", err)
	}
	b.logger.Debug("executor schedule ok")

	// Ensure we have the expected executor primary scheduler role.
	isPrimaryScheduler := schedulerCheckPrimaryScheduler(b.executorCommittee, b.identity.NodeSigner.Public(), round)
	if shouldBePrimaryScheduler != isPrimaryScheduler {
		return nil, fmt.Errorf("not in expected executor primary scheduler role")
	}
	b.logger.Debug("executor primary scheduler role ok")

	// Create a stateless storage client.
	b.storageClient = client.NewStatelessStorage(b.p2p.service, b.chainContext, b.runtimeID)

	return b, nil
}

func waitForEpoch(svc consensus.Service, epoch beacon.EpochTime) error {
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
