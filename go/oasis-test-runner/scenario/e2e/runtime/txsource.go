package runtime

import (
	"context"
	"crypto"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	commonGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/txsource"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/debug/txsource/workload"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	timeLimitShort    = 6 * time.Minute
	timeLimitShortSGX = 6 * time.Minute
	timeLimitLong     = 12 * time.Hour

	nodeRestartIntervalLong = 2 * time.Minute
	nodeLongRestartInterval = 15 * time.Minute
	nodeLongRestartDuration = 10 * time.Minute
	livenessCheckInterval   = 2 * time.Minute
	txSourceGasPrice        = 1

	crashPointProbability = 0.0005
)

// TxSourceMultiShort uses multiple workloads for a short time.
var TxSourceMultiShort scenario.Scenario = &txSourceImpl{
	runtimeImpl: *newRuntimeImpl("txsource-multi-short", nil),
	clientWorkloads: []string{
		workload.NameCommission,
		workload.NameDelegation,
		workload.NameOversized,
		workload.NameParallel,
		workload.NameRegistration,
		workload.NameRuntime,
		workload.NameTransfer,
		workload.NameGovernance,
	},
	allNodeWorkloads: []string{
		workload.NameQueries,
	},
	timeLimit:                         timeLimitShort,
	livenessCheckInterval:             livenessCheckInterval,
	consensusPruneDisabledProbability: 0.1,
	consensusPruneMinKept:             100,
	consensusPruneMaxKept:             200,
	numValidatorNodes:                 4,
	numKeyManagerNodes:                2,
	numComputeNodes:                   4,
	numClientNodes:                    2,
}

// TxSourceMultiShortSGX uses multiple workloads for a short time.
var TxSourceMultiShortSGX scenario.Scenario = &txSourceImpl{
	runtimeImpl: *newRuntimeImpl("txsource-multi-short-sgx", nil),
	clientWorkloads: []string{
		workload.NameCommission,
		workload.NameDelegation,
		workload.NameOversized,
		workload.NameParallel,
		workload.NameRegistration,
		workload.NameRuntime,
		workload.NameTransfer,
		workload.NameGovernance,
	},
	allNodeWorkloads: []string{
		workload.NameQueries,
	},
	timeLimit:                         timeLimitShortSGX,
	livenessCheckInterval:             livenessCheckInterval,
	consensusPruneDisabledProbability: 0.1,
	consensusPruneMinKept:             100,
	consensusPruneMaxKept:             200,
	// XXX: don't use more nodes as SGX E2E test instances cannot handle many
	// more nodes that are currently configured.
	numValidatorNodes:  2,
	numKeyManagerNodes: 1,
	numComputeNodes:    2,
	numClientNodes:     1,
}

// TxSourceMulti uses multiple workloads.
var TxSourceMulti scenario.Scenario = &txSourceImpl{
	runtimeImpl: *newRuntimeImpl("txsource-multi", nil),
	clientWorkloads: []string{
		workload.NameCommission,
		workload.NameDelegation,
		workload.NameOversized,
		workload.NameParallel,
		workload.NameRegistration,
		workload.NameRuntime,
		workload.NameTransfer,
		workload.NameGovernance,
	},
	allNodeWorkloads: []string{
		workload.NameQueries,
	},
	timeLimit:                         timeLimitLong,
	nodeRestartInterval:               nodeRestartIntervalLong,
	nodeLongRestartInterval:           nodeLongRestartInterval,
	nodeLongRestartDuration:           nodeLongRestartDuration,
	livenessCheckInterval:             livenessCheckInterval,
	consensusPruneDisabledProbability: 0.1,
	consensusPruneMinKept:             100,
	consensusPruneMaxKept:             1000,
	enableCrashPoints:                 true,
	// Nodes getting killed commonly result in corrupted tendermint WAL when the
	// node is restarted. Enable automatic corrupted WAL recovery for nodes.
	tendermintRecoverCorruptedWAL: true,
	// Use 4 validators so that consensus can keep making progress when a node
	// is being killed and restarted.
	numValidatorNodes: 4,
	// Use 2 keymanagers so that at least one keymanager is accessible when
	// the other one is being killed or shut down.
	numKeyManagerNodes: 2,
	// In tests with long restarts we want to have 3 worker nodes in the runtime
	// executor worker committee. That is so that each published runtime
	// transaction will be received by at least one active executor worker.
	// In worst case, 2 nodes can be offline at the same time. Aditionally we
	// need one backup node and one extra node.
	numComputeNodes: 5,
	// Second client node is used to run supplementary-sanity checks which can
	// cause the node to fall behind over the long run.
	numClientNodes: 2,
}

type txSourceImpl struct { // nolint: maligned
	runtimeImpl

	clientWorkloads  []string
	allNodeWorkloads []string

	timeLimit               time.Duration
	nodeRestartInterval     time.Duration
	nodeLongRestartInterval time.Duration
	nodeLongRestartDuration time.Duration
	livenessCheckInterval   time.Duration

	consensusPruneDisabledProbability float32
	consensusPruneMinKept             int64
	consensusPruneMaxKept             int64

	tendermintRecoverCorruptedWAL bool

	enableCrashPoints bool

	numValidatorNodes  int
	numKeyManagerNodes int
	numComputeNodes    int
	numClientNodes     int

	rng  *rand.Rand
	seed string
}

func (sc *txSourceImpl) PreInit(childEnv *env.Env) error {
	// Generate a new random seed and log it so we can reproduce the run.
	// Use existing seed, if it already exists.
	if sc.seed == "" {
		rawSeed := make([]byte, 16)
		_, err := cryptoRand.Read(rawSeed)
		if err != nil {
			return fmt.Errorf("failed to generate random seed: %w", err)
		}
		sc.seed = hex.EncodeToString(rawSeed)

		sc.Logger.Info("using random seed",
			"seed", sc.seed,
		)
	}

	// Set up the deterministic random source.
	hash := crypto.SHA512
	src, err := drbg.New(hash, []byte(sc.seed), nil, []byte("txsource scenario"))
	if err != nil {
		return fmt.Errorf("failed to create random source: %w", err)
	}
	sc.rng = rand.New(mathrand.New(src)) //nolint:gosec

	return nil
}

func (sc *txSourceImpl) generateConsensusFixture(f *oasis.ConsensusFixture, forceDisableConsensusPrune bool) {
	// Randomize pruning configuration.
	p := sc.rng.Float32()
	switch {
	case forceDisableConsensusPrune || p < sc.consensusPruneDisabledProbability:
		f.PruneNumKept = 0
	default:
		// [sc.consensusPruneMinKept, sc.consensusPruneMaxKept]
		f.PruneNumKept = uint64(sc.rng.Int63n(sc.consensusPruneMaxKept-sc.consensusPruneMinKept+1) + sc.consensusPruneMinKept)
	}
}

func (sc *txSourceImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}
	// Use deterministic identities as we need to allocate funds to nodes.
	f.Network.DeterministicIdentities = true
	f.Network.GovernanceParameters = &governance.ConsensusParameters{
		VotingPeriod:              10,
		MinProposalDeposit:        *quantity.NewFromUint64(300),
		StakeThreshold:            68,
		UpgradeMinEpochDiff:       40,
		UpgradeCancelMinEpochDiff: 20,
	}
	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			CommissionScheduleRules: staking.CommissionScheduleRules{
				RateChangeInterval: 10,
				RateBoundLead:      30,
				MaxRateSteps:       12,
				MaxBoundSteps:      12,
			},
			DebondingInterval: 2,
			GasCosts: transaction.Costs{
				staking.GasOpTransfer:      10,
				staking.GasOpBurn:          10,
				staking.GasOpAddEscrow:     10,
				staking.GasOpReclaimEscrow: 10,
				staking.GasOpAllow:         10,
				staking.GasOpWithdraw:      10,
			},
			MaxAllowances:             32,
			FeeSplitWeightPropose:     *quantity.NewFromUint64(2),
			FeeSplitWeightVote:        *quantity.NewFromUint64(1),
			FeeSplitWeightNextPropose: *quantity.NewFromUint64(1),
			AllowEscrowMessages:       true,
		},
		TotalSupply: *quantity.NewFromUint64(150000000400),
		Ledger: map[staking.Address]*staking.Account{
			e2e.DeterministicValidator0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicValidator1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicValidator2: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicValidator3: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicCompute0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicCompute1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicCompute2: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicCompute3: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicCompute4: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicStorage0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicStorage1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicStorage2: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicStorage3: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicKeyManager0: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			e2e.DeterministicKeyManager1: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(10000000000),
				},
			},
			// Entity accounts need escrow so that validators have voting power
			// for governance.
			e2e.DeterministicEntity1: {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(100),
					},
				},
			},
			e2e.DeterministicEntity2: {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(100),
					},
				},
			},
			e2e.DeterministicEntity3: {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(100),
					},
				},
			},
			e2e.DeterministicEntity4: {
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(100),
					},
				},
			},
		},
		Delegations: map[staking.Address]map[staking.Address]*staking.Delegation{
			e2e.DeterministicEntity1: {
				e2e.DeterministicEntity1: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100),
				},
			},
			e2e.DeterministicEntity2: {
				e2e.DeterministicEntity2: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100),
				},
			},
			e2e.DeterministicEntity3: {
				e2e.DeterministicEntity3: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100),
				},
			},
			e2e.DeterministicEntity4: {
				e2e.DeterministicEntity4: &staking.Delegation{
					Shares: *quantity.NewFromUint64(100),
				},
			},
		},
	}
	f.Entities = []oasis.EntityCfg{
		{IsDebugTestEntity: true},
	}
	for i := 0; i < sc.numValidatorNodes; i++ {
		f.Entities = append(f.Entities, oasis.EntityCfg{})
	}

	// Runtime configuration.
	// Transaction scheduling.
	f.Runtimes[1].TxnScheduler.MaxBatchSize = 100
	f.Runtimes[1].TxnScheduler.MaxBatchSizeBytes = 1024 * 1024

	// Set up storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 1000
	f.Runtimes[1].Storage.CheckpointNumKept = 2
	f.Runtimes[1].Storage.CheckpointChunkSize = 1024 * 1024

	// Executor committee.
	f.Runtimes[1].Executor.GroupBackupSize = 1
	f.Runtimes[1].Executor.GroupSize = uint16(sc.numComputeNodes) -
		f.Runtimes[1].Executor.GroupBackupSize
	f.Runtimes[1].Constraints[scheduler.KindComputeExecutor][scheduler.RoleWorker].MinPoolSize.Limit = f.Runtimes[1].Executor.GroupSize
	f.Runtimes[1].Constraints[scheduler.KindComputeExecutor][scheduler.RoleBackupWorker].MinPoolSize.Limit = f.Runtimes[1].Executor.GroupBackupSize

	if sc.nodeLongRestartInterval > 0 {
		// One executor can be offline.
		f.Runtimes[1].Executor.GroupSize--
		f.Runtimes[1].Constraints[scheduler.KindComputeExecutor][scheduler.RoleWorker].MinPoolSize.Limit--
		f.Runtimes[1].Constraints[scheduler.KindComputeExecutor][scheduler.RoleBackupWorker].MinPoolSize.Limit--
		// Allow one straggler to handle the case where the backup and primary worker are offline
		// at the same time.
		f.Runtimes[1].Executor.AllowedStragglers = 1

		// Lower proposer and round timeouts as nodes are expected to go offline for longer time.
		f.Runtimes[1].TxnScheduler.ProposerTimeout = 4
		f.Runtimes[1].Executor.RoundTimeout = 10
	}

	if sc.nodeRestartInterval > 0 || sc.nodeLongRestartInterval > 0 {
		// If node restarts enabled, do not enable round timeouts, failures or
		// discrepancy log watchers.
		f.Network.DefaultLogWatcherHandlerFactories = []log.WatcherHandlerFactory{}
	}

	var validators []oasis.ValidatorFixture
	for i := 0; i < sc.numValidatorNodes; i++ {
		validators = append(validators, oasis.ValidatorFixture{
			Entity: i + 1, // Skip 0, which is the test entity.
		})
	}
	f.Validators = validators
	var keymanagers []oasis.KeymanagerFixture
	for i := 0; i < sc.numKeyManagerNodes; i++ {
		keymanagers = append(keymanagers, oasis.KeymanagerFixture{
			Runtime: 0,
			Entity:  1,
		})
	}
	f.Keymanagers = keymanagers
	var computeWorkers []oasis.ComputeWorkerFixture
	for i := 0; i < sc.numComputeNodes; i++ {
		computeWorkers = append(computeWorkers, oasis.ComputeWorkerFixture{
			Entity:   1,
			Runtimes: []int{1},
		})
	}
	f.ComputeWorkers = computeWorkers
	var clients []oasis.ClientFixture
	for i := 0; i < sc.numClientNodes; i++ {
		c := oasis.ClientFixture{}
		// Enable runtime on the first node.
		if i == 0 {
			c.Runtimes = []int{1}
		}
		// Enable supplementary sanity and profiling on the last client node.
		if i == sc.numClientNodes-1 {
			c.Consensus.SupplementarySanityInterval = 1
			c.EnableProfiling = true
		}
		clients = append(clients, c)
	}
	f.Clients = clients

	// Update validators to require fee payments.
	for i := range f.Validators {
		f.Validators[i].Consensus.MinGasPrice = txSourceGasPrice
		f.Validators[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		// Enable recovery from corrupted WAL.
		f.Validators[i].Consensus.TendermintRecoverCorruptedWAL = sc.tendermintRecoverCorruptedWAL
		// Ensure validator-0 does not have pruning enabled, so nodes taken down
		// for long period can sync from it.
		// Note: validator-0 is also never restarted.
		sc.generateConsensusFixture(&f.Validators[i].Consensus, i == 0)
		if i > 0 && sc.enableCrashPoints {
			f.Validators[i].CrashPointsProbability = crashPointProbability
		}
	}
	// Update all other nodes to use a specific gas price.
	for i := range f.Keymanagers {
		f.Keymanagers[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		// Enable recovery from corrupted WAL.
		f.Keymanagers[i].Consensus.TendermintRecoverCorruptedWAL = sc.tendermintRecoverCorruptedWAL
		sc.generateConsensusFixture(&f.Keymanagers[i].Consensus, false)
		if i > 0 && sc.enableCrashPoints {
			f.Keymanagers[i].CrashPointsProbability = crashPointProbability
		}
	}
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		// Enable recovery from corrupted WAL.
		f.ComputeWorkers[i].Consensus.TendermintRecoverCorruptedWAL = sc.tendermintRecoverCorruptedWAL
		sc.generateConsensusFixture(&f.ComputeWorkers[i].Consensus, false)
		if i > 0 && sc.enableCrashPoints {
			f.ComputeWorkers[i].CrashPointsProbability = crashPointProbability
		}
	}
	for i := range f.ByzantineNodes {
		f.ByzantineNodes[i].Consensus.SubmissionGasPrice = txSourceGasPrice
		sc.generateConsensusFixture(&f.ByzantineNodes[i].Consensus, false)
	}

	return f, nil
}

func (sc *txSourceImpl) manager(env *env.Env, errCh chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	// Make sure we exit when the environment gets torn down.
	stopCh := make(chan struct{})
	env.AddOnCleanup(func() {
		cancel()
		close(stopCh)
	})

	if sc.nodeRestartInterval > 0 {
		sc.Logger.Info("random node restarts enabled",
			"restart_interval", sc.nodeRestartInterval,
		)
	} else {
		sc.nodeRestartInterval = math.MaxInt64
	}
	if sc.nodeLongRestartInterval > 0 {
		sc.Logger.Info("random long node restarts enabled",
			"interval", sc.nodeLongRestartInterval,
			"start_delay", sc.nodeLongRestartDuration,
		)
	} else {
		sc.nodeLongRestartInterval = math.MaxInt64
	}

	// Setup restarable nodes.
	var restartableLock sync.Mutex
	var longRestartNode *oasis.Node
	var restartableNodes []*oasis.Node
	// Keep one of each types of nodes always running.
	for _, v := range sc.Net.Validators()[1:] {
		restartableNodes = append(restartableNodes, v.Node)
	}
	for _, c := range sc.Net.ComputeWorkers()[1:] {
		restartableNodes = append(restartableNodes, c.Node)
	}
	for _, k := range sc.Net.Keymanagers()[1:] {
		restartableNodes = append(restartableNodes, k.Node)
	}

	restartTicker := time.NewTicker(sc.nodeRestartInterval)
	defer restartTicker.Stop()

	livenessTicker := time.NewTicker(sc.livenessCheckInterval)
	defer livenessTicker.Stop()

	longRestartTicker := time.NewTicker(sc.nodeLongRestartInterval)
	defer longRestartTicker.Stop()

	var nodeIndex int
	var lastHeight int64
	for {
		select {
		case <-stopCh:
			return
		case <-restartTicker.C:
			func() {
				restartableLock.Lock()
				defer restartableLock.Unlock()

				// Reshuffle nodes each time the counter wraps around.
				if nodeIndex == 0 {
					sc.rng.Shuffle(len(restartableNodes), func(i, j int) {
						restartableNodes[i], restartableNodes[j] = restartableNodes[j], restartableNodes[i]
					})
				}
				// Ensure the current node is not being restarted already.
				if longRestartNode != nil && restartableNodes[nodeIndex].NodeID.Equal(longRestartNode.NodeID) {
					nodeIndex = (nodeIndex + 1) % len(restartableNodes)
				}

				// Choose a random node and restart it.
				node := restartableNodes[nodeIndex]
				sc.Logger.Info("restarting node",
					"node", node.Name,
				)
				if err := node.Restart(ctx); err != nil {
					sc.Logger.Error("failed to restart node",
						"node", node.Name,
						"err", err,
					)
					errCh <- err
					return
				}
				sc.Logger.Info("node restarted",
					"node", node.Name,
				)
				nodeIndex = (nodeIndex + 1) % len(restartableNodes)
			}()
		case <-longRestartTicker.C:
			// Choose a random node and restart it.
			restartableLock.Lock()
			if longRestartNode != nil {
				sc.Logger.Info("node already stopped, skipping",
					"node", longRestartNode,
				)
				restartableLock.Unlock()
				continue
			}

			longRestartNode = restartableNodes[sc.rng.Intn(len(restartableNodes))]
			selectedNode := longRestartNode
			restartableLock.Unlock()
			go func() {
				sc.Logger.Info("stopping node",
					"node", selectedNode.Name,
					"start_delay", sc.nodeLongRestartDuration,
				)
				if err := selectedNode.RestartAfter(ctx, sc.nodeLongRestartDuration); err != nil {
					sc.Logger.Error("failed to restart node",
						"node", selectedNode.Name,
						"err", err,
					)
					errCh <- err
					return
				}
				sc.Logger.Info("starting node",
					"node", selectedNode.Name,
					"start_delay", sc.nodeLongRestartDuration,
				)

				restartableLock.Lock()
				longRestartNode = nil
				restartableLock.Unlock()
			}()

		case <-livenessTicker.C:
			// Check if consensus has made any progress.
			livenessCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			blk, err := sc.Net.Controller().Consensus.GetBlock(livenessCtx, consensus.HeightLatest)
			cancel()
			if err != nil {
				sc.Logger.Warn("failed to query latest consensus block",
					"err", err,
				)
				continue
			}

			if blk.Height <= lastHeight {
				sc.Logger.Error("consensus hasn't made any progress since last liveness check",
					"last_height", lastHeight,
					"height", blk.Height,
				)
				errCh <- fmt.Errorf("consensus is dead")
				return
			}

			sc.Logger.Info("current consensus height",
				"height", blk.Height,
			)

			//
			// Check if the transactions are properly sorted by priority.
			//

			latestHeight := blk.Height

			// Unfortunately, Tendermint doesn't store the priority anywhere,
			// so we need to kludge this a bit.
			priority := map[string]int64{
				"beacon":     100000,
				"keymanager": 50000,
				"registry":   50000,
				"governance": 25000,
				"roothash":   15000,
				"staking":    1000,
			}

			// Make sure that transactions at each height since our last check
			// are properly sorted by their priority.
			var h int64
			for h = lastHeight; h < latestHeight; h++ {
				// Fetch transactions.
				txs, err := sc.Net.Controller().Consensus.GetTransactions(ctx, h)
				if err != nil {
					errCh <- err
					return
				}

				priorities := make([]int64, 0, len(txs))

				for _, rawtx := range txs {
					// Decode transaction.
					var sigTx transaction.SignedTransaction
					if err = cbor.Unmarshal(rawtx, &sigTx); err != nil {
						errCh <- fmt.Errorf("malformed transaction: %w", err)
						return
					}

					var tx transaction.Transaction
					if err = sigTx.Open(&tx); err != nil {
						errCh <- fmt.Errorf("bad transaction signature: %w", err)
						return
					}

					// Determine transaction's priority.
					var pri int64
					if tx.Method == "registry.RegisterNode" {
						// This is currently the only special case.
						pri = 60000
					} else {
						// Determine consensus app from the tx's method.
						app := strings.Split(string(tx.Method), ".")[0]
						if p, exists := priority[app]; exists {
							pri = p
						} else {
							continue
						}
					}

					priorities = append(priorities, pri)
				}

				// All priorities must be sorted from highest to lowest.
				if !sort.SliceIsSorted(priorities, func(i, j int) bool {
					return priorities[i] > priorities[j]
				}) {
					errCh <- fmt.Errorf("transactions at height %d are not sorted by priority", h)
					return
				}
			}

			lastHeight = blk.Height
		}
	}
}

func (sc *txSourceImpl) startWorkload(childEnv *env.Env, errCh chan error, name string, node *oasis.Node) error {
	sc.Logger.Info("starting workload",
		"name", name,
		"node", node.Name,
	)

	d, err := childEnv.NewSubDir(fmt.Sprintf("workload-%s", name))
	if err != nil {
		return err
	}
	d, err = d.NewSubDir(node.Name)
	if err != nil {
		return err
	}

	w, err := d.NewLogWriter(fmt.Sprintf("workload-%s.log", name))
	if err != nil {
		return err
	}

	logFmt := logging.FmtJSON
	logLevel := logging.LevelDebug

	args := []string{
		"debug", "txsource",
		"--address", "unix:" + node.SocketPath(),
		"--" + common.CfgDebugAllowTestKeys,
		"--" + common.CfgDataDir, d.String(),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--log.format", logFmt.String(),
		"--log.level", logLevel.String(),
		"--" + commonGrpc.CfgLogDebug,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
		"--" + workload.CfgRuntimeID, runtimeID.String(),
		"--" + txsource.CfgWorkload, name,
		"--" + txsource.CfgTimeLimit, sc.timeLimit.String(),
		"--" + txsource.CfgSeed, sc.seed,
		"--" + txsource.CfgGasPrice, strconv.FormatUint(txSourceGasPrice, 10),
		// Use half the configured interval due to fast blocks.
		"--" + workload.CfgConsensusNumKeptVersions, strconv.FormatUint(node.Consensus().PruneNumKept/2, 10),
	}
	for _, ent := range sc.Net.Entities()[1:] {
		args = append(args, "--"+txsource.CfgValidatorEntity, ent.EntityKeyPath())
	}
	// Disable runtime queries on non-client node.
	if node.Name != sc.Net.Clients()[0].Name {
		args = append(args, "--"+workload.CfgQueriesRuntimeEnabled+"=false")
	}
	nodeBinary := sc.Net.Config().NodeBinary

	cmd := exec.Command(nodeBinary, args...)
	cmd.SysProcAttr = env.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	// Setup verbose http2 requests logging for nodes. Investigating EOF gRPC
	// failures.
	if name == workload.NameQueries {
		cmd.Env = append(os.Environ(),
			"GODEBUG=http2debug=1",
		)
	}

	sc.Logger.Info("launching workload binary",
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return err
	}

	go func() {
		waitErr := cmd.Wait()
		errCh <- waitErr

		sc.Logger.Info("workload finished",
			"name", name,
			"node", node.Name,
			"err", waitErr,
		)
	}()

	return nil
}

func (sc *txSourceImpl) Clone() scenario.Scenario {
	return &txSourceImpl{
		runtimeImpl:                       *sc.runtimeImpl.Clone().(*runtimeImpl),
		clientWorkloads:                   sc.clientWorkloads,
		allNodeWorkloads:                  sc.allNodeWorkloads,
		timeLimit:                         sc.timeLimit,
		nodeRestartInterval:               sc.nodeRestartInterval,
		nodeLongRestartDuration:           sc.nodeLongRestartDuration,
		nodeLongRestartInterval:           sc.nodeLongRestartInterval,
		livenessCheckInterval:             sc.livenessCheckInterval,
		consensusPruneDisabledProbability: sc.consensusPruneDisabledProbability,
		consensusPruneMinKept:             sc.consensusPruneMinKept,
		consensusPruneMaxKept:             sc.consensusPruneMaxKept,
		tendermintRecoverCorruptedWAL:     sc.tendermintRecoverCorruptedWAL,
		enableCrashPoints:                 sc.enableCrashPoints,
		numValidatorNodes:                 sc.numValidatorNodes,
		numKeyManagerNodes:                sc.numKeyManagerNodes,
		numComputeNodes:                   sc.numComputeNodes,
		numClientNodes:                    sc.numClientNodes,
		seed:                              sc.seed,
		// rng must always be reinitialized from seed by calling PreInit().
	}
}

func (sc *txSourceImpl) Run(childEnv *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return fmt.Errorf("scenario net Start: %w", err)
	}

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	ctx := context.Background()

	sc.Logger.Info("waiting for network to come up")
	if err := sc.Net.Controller().WaitNodesRegistered(ctx, sc.Net.NumRegisterNodes()); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	// Start all configured workloads.
	errCh := make(chan error, len(sc.clientWorkloads)+len(sc.allNodeWorkloads)+2)
	for _, name := range sc.clientWorkloads {
		if err := sc.startWorkload(childEnv, errCh, name, sc.Net.Clients()[0].Node); err != nil {
			return fmt.Errorf("failed to start client workload %s: %w", name, err)
		}
	}
	nodes := sc.Net.Nodes()
	for _, name := range sc.allNodeWorkloads {
		for _, node := range nodes {
			if err := sc.startWorkload(childEnv, errCh, name, node); err != nil {
				return fmt.Errorf("failed to start workload %s on node %s: %w", name, node.Name, err)
			}
		}
	}
	// Start background scenario manager.
	go sc.manager(childEnv, errCh)

	// Wait for any workload to terminate.
	var err error
	select {
	case err = <-sc.Net.Errors():
	case err = <-errCh:
	}
	if err != nil {
		return err
	}

	if err = sc.Net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}
