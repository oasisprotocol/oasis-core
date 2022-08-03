package workload

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction/results"
	tmcrypto "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

// NameQueries is the name of the queries workload.
const NameQueries = "queries"

// Queries is the queries workload.
var Queries = &queries{}

const (
	// CfgConsensusNumKeptVersions is the number of last consensus state versions that the nodes are
	// keeping (e.g., due to a configured pruning policy). Versions older than that will not be
	// queried.
	//
	// Note that this is only for consensus state versions, not runtime versions.
	CfgConsensusNumKeptVersions = "queries.consensus.num_kept_versions"
	// CfgQueriesRuntimeEnabled configures whether runtime queries are enabled.
	CfgQueriesRuntimeEnabled = "queries.runtime.enabled"

	// Ratio of queries that should query height 1.
	queriesEarliestHeightRatio = 0.1
	// Ratio of queries that should query latest available height.
	queriesLatestHeightRatio = 0.1
	// Ratio of consensus state integrity queries.
	queriesConsensusStateIntegrityRatio = 0.05

	// queriesIterationTimeout is the combined timeout for running all the queries that are executed
	// in a single iteration. The purpose of this timeout is to prevent the client being stuck and
	// treating that as an error instead.
	queriesIterationTimeout = 300 * time.Second

	// doQueryAllProposalsEvery configures how often the queries workload should query all (including)
	// past proposals.
	doQueryAllProposalsEvery = 10
)

// QueriesFlags are the queries workload flags.
var QueriesFlags = flag.NewFlagSet("", flag.ContinueOnError)

type queries struct {
	logger *logging.Logger

	runtimeID       common.Namespace
	epochtimeParams *beacon.ConsensusParameters
	stakingParams   *staking.ConsensusParameters
	schedulerParams *scheduler.ConsensusParameters

	control    control.NodeController
	beacon     beacon.Backend
	staking    staking.Backend
	consensus  consensus.ClientBackend
	registry   registry.Backend
	scheduler  scheduler.Backend
	governance governance.Backend
	runtime    runtimeClient.RuntimeClient

	runtimeGenesisRound uint64

	iteration        uint64
	queryingEarliest bool
}

func (q *queries) sanityCheckTransactionEvents(ctx context.Context, height int64, txEvents []*results.Event) error {
	// Ensure transaction events match querying backend GetEvents methods.
	registryEvents, err := q.registry.GetEvents(ctx, height)
	if err != nil {
		return fmt.Errorf("registry.GetEvents error at height %d: %w", height, err)
	}
	expectedRegistryEvents := make(map[hash.Hash]int)
	for _, event := range registryEvents {
		if event.TxHash.IsEmpty() {
			continue
		}
		h := hash.NewFromBytes(cbor.Marshal(event)[:])
		expectedRegistryEvents[h] = expectedRegistryEvents[h] + 1
	}

	stakingEvents, err := q.staking.GetEvents(ctx, height)
	if err != nil {
		return fmt.Errorf("staking.GetEvents error at height %d: %w", height, err)
	}
	expectedStakingEvents := make(map[hash.Hash]int)
	for _, event := range stakingEvents {
		if event.TxHash.IsEmpty() {
			continue
		}
		h := hash.NewFromBytes(cbor.Marshal(event)[:])
		expectedStakingEvents[h] = expectedStakingEvents[h] + 1
	}

	governanceEvents, err := q.governance.GetEvents(ctx, height)
	if err != nil {
		return fmt.Errorf("governance.GetEvents error at height %d: %w", height, err)
	}
	expectedGovernanceEvents := make(map[hash.Hash]int)
	for _, event := range governanceEvents {
		if event.TxHash.IsEmpty() {
			continue
		}
		h := hash.NewFromBytes(cbor.Marshal(event)[:])
		expectedGovernanceEvents[h] = expectedGovernanceEvents[h] + 1
	}

	for _, txEvent := range txEvents {
		var (
			expectedEvents map[hash.Hash]int
			event          interface{}
		)
		switch {
		case txEvent.Registry != nil:
			expectedEvents = expectedRegistryEvents
			event = txEvent.Registry
		case txEvent.Staking != nil:
			expectedEvents = expectedStakingEvents
			event = txEvent.Staking
		case txEvent.Governance != nil:
			expectedEvents = expectedGovernanceEvents
			event = txEvent.Governance
		case txEvent.RootHash != nil:
			// XXX: we cannot get roothash events from a client.
			continue
		default:
			return fmt.Errorf("unsupported event: %+v", txEvent)
		}
		h := hash.NewFromBytes(cbor.Marshal(event)[:])

		// Make sure that the event is expected.
		switch {
		case expectedEvents[h] == 1:
			// Remove the event from expected events map as counter reached zero.
			delete(expectedEvents, h)
		case expectedEvents[h] < 1:
			// Unexpected event.
			q.logger.Error("GetTransactionsWithResults produced an unexpected event",
				"transaction_event", txEvent,
				"registry_events", registryEvents,
				"staking_events", stakingEvents,
				"height", height,
			)
			return fmt.Errorf("GetTransactionsWithResults produced an unexpected event")
		default:
			// More events remaining.
			expectedEvents[h] = expectedEvents[h] - 1
		}
	}

	// All expected events should be seen.
	if len(expectedRegistryEvents) != 0 {
		q.logger.Error("GetTransactionsWithResults did not produce all expected registry events",
			"missing_events", expectedRegistryEvents,
		)
		return fmt.Errorf("GetTransactionsWithResults did not produce all expected registry events")
	}
	if len(expectedStakingEvents) != 0 {
		q.logger.Error("GetTransactionsWithResults did not produce all expected staking events",
			"missing_events", expectedStakingEvents,
		)
		return fmt.Errorf("GetTransactionsWithResults did not produce all expected staking events")
	}

	return nil
}

// doConsensusQueries does GetBlock, GetTransaction queries for the provided
// height.
func (q *queries) doConsensusQueries(ctx context.Context, rng *rand.Rand, height int64) error {
	q.logger.Debug("doing consensus queries",
		"height", height,
	)

	epoch, err := q.beacon.GetEpoch(ctx, height)
	if err != nil {
		return fmt.Errorf("GetEpoch at height %d: %w", height, err)
	}
	block, err := q.consensus.GetBlock(ctx, height)
	if err != nil {
		return fmt.Errorf("GetBlock at height %d: %w", height, err)
	}
	if block.Height != height {
		return fmt.Errorf("block.Height: %d == %d violated", block.Height, height)
	}
	if params := q.epochtimeParams.InsecureParameters; params != nil && !q.epochtimeParams.DebugMockBackend {
		expectedEpoch := beacon.EpochTime(block.Height / params.Interval)
		if expectedEpoch != epoch {
			q.logger.Error("invalid epoch",
				"expected", expectedEpoch,
				"epoch", epoch,
				"height", block.Height,
				"epoch_interval", params.Interval,
			)
			return fmt.Errorf("invalid epoch: %d", epoch)
		}
	}

	txs, err := q.consensus.GetTransactions(ctx, height)
	if err != nil {
		return fmt.Errorf("GetTransactions at height %d: %w", height, err)
	}

	txsWithRes, err := q.consensus.GetTransactionsWithResults(ctx, height)
	if err != nil {
		q.logger.Error("GetTransactionsWithResults",
			"txs", txs,
			"txs_with_results", txsWithRes,
			"height", height,
			"err", err,
			"status", cmnGrpc.GetErrorStatus(err),
		)
		if st := cmnGrpc.GetErrorStatus(err); st != nil {
			s := status.Error(codes.Internal, io.ErrUnexpectedEOF.Error())
			if st.Err().Error() == s.Error() {
				// XXX: Connection seems to get occasionally reset with
				// FLOW_CONTROL_ERROR in GetTransactionsWithResult during
				// long-term tests, don't fail on this error until we
				// investigate this further.
				// https://github.com/oasisprotocol/oasis-core/issues/3334
				return nil
			}
		}
		return fmt.Errorf("GetTransactionsWithResults at height %d: %w", height, err)
	}
	if len(txs) != len(txsWithRes.Transactions) {
		q.logger.Error("GetTransactionsWithResults transactions length mismatch",
			"txs", txs,
			"txs_with_results", txsWithRes,
			"height", height,
		)
		return fmt.Errorf(
			"GetTransactionsWithResults transactions length mismatch, expected: %d, got: %d",
			len(txs), len(txsWithRes.Transactions),
		)
	}
	if len(txsWithRes.Transactions) != len(txsWithRes.Results) {
		q.logger.Error("GetTransactionsWithResults results length mismatch",
			"txs", txs,
			"txs_with_results", txsWithRes,
			"height", height,
		)
		return fmt.Errorf(
			"GetTransactionsWithResults results length mismatch, expected: %d, got: %d",
			len(txsWithRes.Transactions), len(txsWithRes.Results),
		)
	}

	var txEvents []*results.Event
	for _, res := range txsWithRes.Results {
		txEvents = append(txEvents, res.Events...)
	}
	if err := q.sanityCheckTransactionEvents(ctx, height, txEvents); err != nil {
		return fmt.Errorf("GetTransactionsWithResults events sanity check error: %w", err)
	}

	// Verify state integrity by iterating over all keys.
	if height > 1 && rng.Float32() < queriesConsensusStateIntegrityRatio {
		q.logger.Debug("verifying state integrity",
			"state_root", block.StateRoot,
		)
		state := mkvs.NewWithRoot(q.consensus.State(), nil, block.StateRoot)
		defer state.Close()

		it := state.NewIterator(ctx, mkvs.IteratorPrefetch(100))
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
		}
		if err := it.Err(); err != nil {
			return fmt.Errorf("consensus state iteration failed: %w", err)
		}
		q.logger.Debug("state integrity verified")
	}

	q.logger.Debug("consensus queries done",
		"height", height,
		"epoch", epoch,
		"block", block,
	)

	return nil
}

// doSchedulerQueries does GetCommittees and GetValidator queries for the
// provided height.
func (q *queries) doSchedulerQueries(ctx context.Context, rng *rand.Rand, height int64) error {
	q.logger.Debug("doing scheduler queries",
		"height", height,
	)

	validators, err := q.scheduler.GetValidators(ctx, height)
	if err != nil {
		return fmt.Errorf("GetValidators at height %d: %w", height, err)
	}
	if len(validators) < q.schedulerParams.MinValidators {
		return fmt.Errorf("not enough validators at height %d, expected at least: %d, got: %d", height, q.schedulerParams.MinValidators, len(validators))
	}

	// Query commiteess for the runtime.
	committees, err := q.scheduler.GetCommittees(ctx, &scheduler.GetCommitteesRequest{
		Height:    height,
		RuntimeID: q.runtimeID,
	})
	if err != nil {
		return fmt.Errorf("GetCommittees at height %d: %w", height, err)
	}
	epoch, err := q.beacon.GetEpoch(ctx, height)
	if err != nil {
		return fmt.Errorf("GetEpoch failure: %w", err)
	}
	// In the E2E-tests only validators are present in the genesis documents,
	// meaning there will be no other committees in the first epoch (epoch=0).
	// In epoch 1 the key-manager will register, but not yet compute/storage
	// workers, since those will wait for key-manager committee to be available.
	// This means that compute/storage nodes will register during epoch 2 and
	// the committee should be elected from epoch 4 onward.
	if epoch > 3 {
		if committees == nil {
			q.logger.Error("missing committee for simple-keyvalue runtime",
				"height", height,
				"epoch", epoch,
				"runtime_id", q.runtimeID,
			)
			return fmt.Errorf("missing commiteess")
		}
	}

	q.logger.Debug("scheduler queries done",
		"height", height,
		"validators", validators,
		"committees", committees,
	)

	return nil
}

// doRegistryQueries does registry queries for the provided height.
func (q *queries) doRegistryQueries(ctx context.Context, rng *rand.Rand, height int64) error {
	q.logger.Debug("doing registry queries",
		"height", height,
	)

	// Entities.
	ents, err := q.registry.GetEntities(ctx, height)
	if err != nil {
		return fmt.Errorf("GetEntities error at height %d: %w", height, err)
	}
	// Entities should exist at every height.
	if len(ents) == 0 {
		return fmt.Errorf("GetEntities empty response at height %d", height)
	}
	// Query each entity individually.
	for _, ent := range ents {
		var entity *entity.Entity
		entity, err = q.registry.GetEntity(ctx, &registry.IDQuery{ID: ent.ID, Height: height})
		if err != nil {
			return fmt.Errorf("GetEntity error at height %d: %w", height, err)
		}
		if !ent.ID.Equal(entity.ID) {
			return fmt.Errorf("GetEntity mismatch, expected: %s, got: %s", ent, entity)
		}
	}

	// Nodes.
	nodes, err := q.registry.GetNodes(ctx, height)
	if err != nil {
		return fmt.Errorf("GetNodes error at height %d: %w", height, err)
	}
	if len(nodes) == 0 {
		return fmt.Errorf("GetNodes empty response at height %d", height)
	}
	for _, nod := range nodes {
		var node *node.Node
		node, err = q.registry.GetNode(ctx, &registry.IDQuery{ID: nod.ID, Height: height})
		if err != nil {
			return fmt.Errorf("GetNode error at height %d: %w", height, err)
		}
		if !nod.ID.Equal(node.ID) {
			return fmt.Errorf("GetNode mismatch, expected: %s, got: %s", nod, node)
		}
		_, err = q.registry.GetNodeStatus(ctx, &registry.IDQuery{ID: nod.ID, Height: height})
		if err != nil {
			return fmt.Errorf("GetNodeStatus error at height %d: %w", height, err)
		}
		node, err = q.registry.GetNodeByConsensusAddress(
			ctx,
			&registry.ConsensusAddressQuery{
				Address: []byte(tmcrypto.PublicKeyToTendermint(&nod.Consensus.ID).Address()), Height: height,
			},
		)
		if err != nil {
			return fmt.Errorf("GetNodeByConsensusAddress error at height %d: %w", height, err)
		}
		if !nod.ID.Equal(node.ID) {
			return fmt.Errorf("GetNodeByConsensusAddress mismatch, expected: %s, got: %s", nod, node)
		}
	}

	// Runtimes.
	runtimes, err := q.registry.GetRuntimes(ctx, &registry.GetRuntimesQuery{Height: height, IncludeSuspended: false})
	if err != nil {
		return fmt.Errorf("GetRuntimes(IncludeSuspended=false) error at height %d: %w", height, err)
	}
	if len(runtimes) == 0 {
		return fmt.Errorf("GetRuntimes(IncludeSuspended=false) empty response at height %d", height)
	}
	for _, rt := range runtimes {
		var runtime *registry.Runtime
		runtime, err = q.registry.GetRuntime(ctx, &registry.GetRuntimeQuery{ID: rt.ID, Height: height})
		if err != nil {
			return fmt.Errorf("GetRuntime error at height %d: %w", height, err)
		}
		if !rt.ID.Equal(&runtime.ID) {
			return fmt.Errorf("GetRuntime mismatch, expected: %s, got: %s", rt, runtime)
		}
	}
	allRuntimes, err := q.registry.GetRuntimes(ctx, &registry.GetRuntimesQuery{Height: height, IncludeSuspended: true})
	if err != nil {
		return fmt.Errorf("GetRuntimes(IncludeSuspended=true) error at height %d: %w", height, err)
	}
	if len(allRuntimes) < len(runtimes) {
		return fmt.Errorf("GetRuntimes(IncludeSuspended=true) returned less runtimes than IncludeSuspended=false, at height %d", height)
	}

	// Events.
	_, err = q.registry.GetEvents(ctx, height)
	if err != nil {
		return fmt.Errorf("GetEvents error at height %d: %w", height, err)
	}

	q.logger.Debug("done registry queries",
		"height", height,
	)

	return nil
}

// doStakingQueries does staking queries at the provided height.
func (q *queries) doStakingQueries(ctx context.Context, rng *rand.Rand, height int64) error {
	q.logger.Debug("doing staking queries",
		"height", height,
	)

	total, err := q.staking.TotalSupply(ctx, height)
	if err != nil {
		return fmt.Errorf("staking.TotalSupply: %w", err)
	}

	commonPool, err := q.staking.CommonPool(ctx, height)
	if err != nil {
		return fmt.Errorf("staking.CommonPool: %w", err)
	}

	lastBlockFees, err := q.staking.LastBlockFees(ctx, height)
	if err != nil {
		return fmt.Errorf("staking.LastBLockFees: %w", err)
	}

	governanceDeposits, err := q.staking.GovernanceDeposits(ctx, height)
	if err != nil {
		return fmt.Errorf("staking.GovernanceDeposits: %w", err)
	}

	thKind := staking.ThresholdKinds[rng.Intn(len(staking.ThresholdKinds))]
	threshold, err := q.staking.Threshold(ctx, &staking.ThresholdQuery{
		Height: height,
		Kind:   thKind,
	})
	if err != nil {
		return fmt.Errorf("staking.Treshold: %w", err)
	}
	expected := q.stakingParams.Thresholds[thKind]
	if threshold.Cmp(&expected) != 0 {
		q.logger.Error("invalid treshold",
			"expected", expected,
			"threshold", threshold,
			"height", height,
		)
		return fmt.Errorf("invalid treshold")
	}

	addresses, err := q.staking.Addresses(ctx, height)
	if err != nil {
		return fmt.Errorf("staking.Addresses: %w", err)
	}

	// Make sure total supply matches sum of all balances and fees.
	var accSum, totalSum quantity.Quantity
	for _, addr := range addresses {
		acc, err := q.staking.Account(ctx, &staking.OwnerQuery{Owner: addr, Height: height})
		if err != nil {
			q.logger.Error("error querying account",
				"height", height,
				"address", addr,
				"err", err,
			)
			return fmt.Errorf("staking.Account: %w", err)
		}
		_ = accSum.Add(&acc.General.Balance)
		_ = accSum.Add(&acc.Escrow.Active.Balance)
		_ = accSum.Add(&acc.Escrow.Debonding.Balance)

		for beneficiary, allowance := range acc.General.Allowances {
			aw, err := q.staking.Allowance(ctx, &staking.AllowanceQuery{
				Height:      height,
				Owner:       addr,
				Beneficiary: beneficiary,
			})
			if err != nil {
				q.logger.Error("error querying allowance",
					"height", height,
					"owner", addr,
					"beneficiary", beneficiary,
					"err", err,
				)
				return fmt.Errorf("staking.Allowance: %w", err)
			}

			if allowance.Cmp(aw) != 0 {
				q.logger.Error("allowance mismatch",
					"height", height,
					"owner", addr,
					"beneficiary", beneficiary,
					"expected", allowance,
					"actual", aw,
				)
				return fmt.Errorf("inconsistent allowance")
			}
		}
	}
	_ = totalSum.Add(commonPool)
	_ = totalSum.Add(governanceDeposits)
	_ = totalSum.Add(lastBlockFees)
	_ = totalSum.Add(&accSum)

	if total.Cmp(&totalSum) != 0 {
		q.logger.Error("staking total supply mismatch",
			"height", height,
			"common_pool", commonPool,
			"governance_deposits", governanceDeposits,
			"last_block_fees", lastBlockFees,
			"accounts_sum", accSum,
			"total_sum", totalSum,
			"total", total,
			"n_addresses", len(addresses),
		)
		return fmt.Errorf("staking total supply mismatch")
	}

	// Events.
	_, grr := q.staking.GetEvents(ctx, height)
	if grr != nil {
		return fmt.Errorf("GetEvents error at height %d: %w", height, grr)
	}

	q.logger.Debug("done staking queries",
		"height", height,
		"total", total,
		"common_pool", commonPool,
		"governance_deposits", governanceDeposits,
		"last_block_fees", lastBlockFees,
		"threshold", threshold,
	)

	return nil
}

// doGovernanceQueries does governance queries at the provided height.
func (q *queries) doGovernanceQueries(ctx context.Context, rng *rand.Rand, height int64) error {
	q.logger.Debug("doing governance queries",
		"height", height,
	)

	proposals, err := q.governance.Proposals(ctx, height)
	if err != nil {
		return fmt.Errorf("governance.Proposals: %w", err)
	}

	// Avoid querying all proposals if we're querying earliest available round,
	// as there can be a lot of proposals and the round could get pruned mid-iteration.
	if q.iteration%doQueryAllProposalsEvery == 0 && !q.queryingEarliest {
		for _, p := range proposals {
			var p2 *governance.Proposal
			p2, err = q.governance.Proposal(ctx, &governance.ProposalQuery{Height: height, ProposalID: p.ID})
			if err != nil {
				return fmt.Errorf("governance.Proposal: %w", err)
			}
			if !p.Content.Equals(&p2.Content) {
				return fmt.Errorf("proposal contents not equal")
			}

			_, err = q.governance.Votes(ctx, &governance.ProposalQuery{Height: height, ProposalID: p.ID})
			if err != nil {
				return fmt.Errorf("governance.Votes: %w", err)
			}
		}
	}

	_, err = q.governance.ActiveProposals(ctx, height)
	if err != nil {
		return fmt.Errorf("governance.ActiveProposals: %w", err)
	}

	pendingUpgrades, err := q.governance.PendingUpgrades(ctx, height)
	if err != nil {
		return fmt.Errorf("governance.PendingUpgrades: %w", err)
	}
	for _, pu := range pendingUpgrades {
		if err = pu.ValidateBasic(); err != nil {
			return fmt.Errorf("invalid pending upgrade: %w", err)
		}
	}

	q.logger.Debug("done governance queries",
		"height", height,
	)
	return nil
}

// doRuntimeQueries does runtime queries at a random round.
func (q *queries) doRuntimeQueries(ctx context.Context, rng *rand.Rand) error {
	q.logger.Debug("doing runtime queries")

	// Latest block.
	latestBlock, err := q.runtime.GetBlock(ctx, &runtimeClient.GetBlockRequest{
		RuntimeID: q.runtimeID,
		Round:     runtimeClient.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("runtimeClient.GetBlock, round: latest: %w", err)
	}
	latestRound := latestBlock.Header.Round

	// Select round at which queries should be done. Earliest (round=1)
	// is special cased with increased probability.
	var round uint64
	p := rng.Float32()
	switch {
	case p < queriesEarliestHeightRatio:
		round = q.runtimeGenesisRound
	case p < queriesEarliestHeightRatio+queriesLatestHeightRatio:
		round = latestRound
	default:
		// [q.runtimeGenesisRound, latestRound]
		round = uint64(rng.Int63n(int64(latestRound-q.runtimeGenesisRound)+1)) + q.runtimeGenesisRound
	}

	// GetBlock.
	block, err := q.runtime.GetBlock(ctx, &runtimeClient.GetBlockRequest{
		RuntimeID: q.runtimeID,
		Round:     round,
	})
	if err != nil {
		q.logger.Error("runtime GetBlock failure",
			"round", round,
			"latest_round", latestRound,
			"err", err,
		)
		return fmt.Errorf("runtimeClient.GetBlock, round: %d: %w", round, err)
	}

	q.logger.Debug("done runtime queries",
		"latest_round", latestRound,
		"block", block,
		"round", round,
	)

	return nil
}

func (q *queries) doControlQueries(ctx context.Context, rng *rand.Rand) error {
	q.logger.Debug("doing node control queries")

	_, err := q.control.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("control.GetStatus error: %w", err)
	}

	q.logger.Debug("done node control queries")

	return nil
}

func (q *queries) doQueries(ctx context.Context, rng *rand.Rand) error {
	block, err := q.consensus.GetBlock(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("consensus.GetBlock error: %w", err)
	}

	// Determine the earliest height that we can query.
	earliestHeight := int64(1)
	if numKept := viper.GetInt64(CfgConsensusNumKeptVersions); numKept < block.Height {
		earliestHeight = block.Height - numKept
	}

	// Select height at which queries should be done. Earliest and latest
	// heights are special cased with increased probability to be selected.
	q.queryingEarliest = false
	var height int64
	p := rng.Float32()
	switch {
	case p < queriesEarliestHeightRatio:
		height = earliestHeight
		q.queryingEarliest = true
	case p < queriesEarliestHeightRatio+queriesLatestHeightRatio:
		height = block.Height
	default:
		// [earliestHeight, block.Height]
		height = rng.Int63n(block.Height-earliestHeight+1) + earliestHeight
	}

	q.logger.Debug("doing queries",
		"height", height,
		"height_latest", block.Height,
	)

	if err := q.doControlQueries(ctx, rng); err != nil {
		return fmt.Errorf("control queries error: %w", err)
	}
	if err := q.doConsensusQueries(ctx, rng, height); err != nil {
		return fmt.Errorf("consensus queries error: %w", err)
	}
	if err := q.doSchedulerQueries(ctx, rng, height); err != nil {
		return fmt.Errorf("scheduler queries error: %w", err)
	}
	if err := q.doRegistryQueries(ctx, rng, height); err != nil {
		return fmt.Errorf("registry queries error: %w", err)
	}
	if err := q.doStakingQueries(ctx, rng, height); err != nil {
		return fmt.Errorf("staking queries error: %w", err)
	}
	if err := q.doGovernanceQueries(ctx, rng, height); err != nil {
		return fmt.Errorf("governance queries error: %w", err)
	}
	if viper.GetBool(CfgQueriesRuntimeEnabled) {
		if err := q.doRuntimeQueries(ctx, rng); err != nil {
			return fmt.Errorf("runtime queries error: %w", err)
		}
	}

	q.logger.Debug("queries done",
		"height", height,
		"height_latest", block.Height,
	)

	return nil
}

// Implements Workload.
func (q *queries) NeedsFunds() bool {
	return false
}

// Implements Workload.
func (q *queries) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	fundingAccount signature.Signer,
	validatorEntities []signature.Signer,
) error {
	var err error
	ctx := context.Background()

	q.logger = logging.GetLogger("cmd/txsource/workload/queries")

	q.control = control.NewNodeControllerClient(conn)
	q.consensus = cnsc
	q.beacon = beacon.NewBeaconClient(conn)
	q.registry = registry.NewRegistryClient(conn)
	q.runtime = runtimeClient.NewRuntimeClient(conn)
	q.scheduler = scheduler.NewSchedulerClient(conn)
	q.governance = governance.NewGovernanceClient(conn)
	q.staking = staking.NewStakingClient(conn)

	q.stakingParams, err = q.staking.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to query staking consensus parameters: %w", err)
	}
	q.schedulerParams, err = q.scheduler.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to query scheduler consensus parameters: %w", err)
	}
	q.epochtimeParams, err = q.beacon.ConsensusParameters(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to query epochtime consensus parameters: %w", err)
	}

	// Setup simple-keyvalue runtime info.
	err = q.runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID))
	if err != nil {
		q.logger.Error("runtime unmarshal error",
			"err", err,
			"runtime_id", viper.GetString(CfgRuntimeID),
		)
		return fmt.Errorf("runtime unmarshal: %w", err)
	}

	if viper.GetBool(CfgQueriesRuntimeEnabled) {
		// Only query genesis block info if runtime queries are enabled.
		resp, err := q.runtime.GetGenesisBlock(ctx, q.runtimeID)
		if err != nil {
			return fmt.Errorf("error querying runtime genesis block: %w", err)
		}
		q.runtimeGenesisRound = resp.Header.Round

		// Wait for 3rd epoch, so that runtimes are up and running.
		q.logger.Info("waiting for 3rd epoch")
		if err := q.beacon.WaitEpoch(ctx, 3); err != nil {
			return fmt.Errorf("failed waiting for 2nd epoch: %w", err)
		}
	}

	for {
		loopCtx, cancel := context.WithTimeout(ctx, queriesIterationTimeout)

		err := q.doQueries(loopCtx, rng)
		cancel()
		switch {
		case err == nil:
		case cmnGrpc.IsErrorCode(err, codes.Unavailable):
			// Don't fail when the node is unavailable as it may be restarting.
			// If the node was shutdown unexpectedly the test runner will fail
			// the test.
			q.logger.Warn("node unavailable, retrying",
				"err", err,
			)
		default:
			return err
		}
		q.iteration++

		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			q.logger.Debug("time's up")
			return nil
		}
	}
}

func init() {
	QueriesFlags.Int64(CfgConsensusNumKeptVersions, 0, "Number of last versions kept by nodes")
	QueriesFlags.Bool(CfgQueriesRuntimeEnabled, true, "Whether runtime queries should be enabled")
	_ = viper.BindPFlags(QueriesFlags)
}
