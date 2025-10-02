package scheduler

import (
	"os"
	"testing"

	"github.com/cometbft/cometbft/abci/types"
	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestDiffValidators(t *testing.T) {
	logger := logging.GetLogger("TestDiffValidators")
	powerOne := map[signature.PublicKey]*scheduler.Validator{
		{}: {
			ID:          signature.PublicKey{},
			EntityID:    signature.PublicKey{},
			VotingPower: 1,
		},
	}
	powerTwo := map[signature.PublicKey]*scheduler.Validator{
		{}: {
			ID:          signature.PublicKey{},
			EntityID:    signature.PublicKey{},
			VotingPower: 2,
		},
	}
	for _, tt := range []struct {
		msg     string
		current map[signature.PublicKey]*scheduler.Validator
		pending map[signature.PublicKey]*scheduler.Validator
		result  []types.ValidatorUpdate
	}{
		{
			msg:     "equal",
			current: powerOne,
			pending: powerOne,
			result:  nil,
		},
		{
			msg:     "add",
			current: nil,
			pending: powerOne,
			result: []types.ValidatorUpdate{
				api.PublicKeyToValidatorUpdate(signature.PublicKey{}, 1),
			},
		},
		{
			msg:     "change",
			current: powerOne,
			pending: powerTwo,
			result: []types.ValidatorUpdate{
				api.PublicKeyToValidatorUpdate(signature.PublicKey{}, 2),
			},
		},
		{
			msg:     "remove",
			current: powerOne,
			pending: nil,
			result: []types.ValidatorUpdate{
				api.PublicKeyToValidatorUpdate(signature.PublicKey{}, 0),
			},
		},
	} {
		require.Equal(t, tt.result, diffValidators(logger, tt.current, tt.pending), tt.msg)
	}
}

func TestElectCommittee(t *testing.T) {
	if testing.Verbose() {
		// Initialize logging to aid debugging.
		_ = logging.Initialize(os.Stdout, logging.FmtLogfmt, logging.LevelDebug, map[string]logging.Level{})
	}

	require := require.New(t)

	appState := api.NewMockApplicationState(&api.MockApplicationStateConfig{})
	ctx := appState.NewContext(api.ContextBeginBlock)
	defer ctx.Close()

	app := &Application{
		state: appState,
	}

	schedulerParameters := &scheduler.ConsensusParameters{}

	schedulerState := schedulerState.NewMutableState(ctx.State())

	epoch := beacon.EpochTime(1)
	beaconState := beaconState.NewMutableState(ctx.State())
	_ = beaconState.DebugForceSetBeacon(ctx, []byte("mock random beacon mock random beacon mock random beacon!!"))
	_ = beaconState.SetEpoch(ctx, epoch, 69)

	beaconParameters := &beacon.ConsensusParameters{
		Backend: beacon.BackendInsecure,
	}

	registryParameters := &registry.ConsensusParameters{}

	rtID1 := common.NewTestNamespaceFromSeed([]byte("runtime 1"), 0)
	rtID2 := common.NewTestNamespaceFromSeed([]byte("runtime 2"), 0)

	nodeID1 := signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000001")
	nodeID2 := signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000002")
	nodeID3 := signature.NewPublicKey("0000000000000000000000000000000000000000000000000000000000000003")

	entityID1 := signature.NewPublicKey("1000000000000000000000000000000000000000000000000000000000000001")
	entityID2 := signature.NewPublicKey("1000000000000000000000000000000000000000000000000000000000000002")

	for _, tc := range []struct {
		msg               string
		kind              scheduler.CommitteeKind
		nodes             []*node.Node
		nodeStatuses      map[signature.PublicKey]*registry.NodeStatus
		validatorEntities map[staking.Address]bool
		rt                registry.Runtime
		shouldElect       bool
	}{
		{
			"executor: should not elect when everything is empty",
			scheduler.KindComputeExecutor,
			[]*node.Node{},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{},
			false,
		},
		{
			"executor: should elect single node with no constraints",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID: nodeID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID: nodeID3,
					Runtimes: []*node.Runtime{
						{ID: rtID2}, // Different runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       1,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			true,
		},
		{
			"executor: only node not for the correct runtime",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID:       nodeID1,
					Runtimes: []*node.Runtime{{ID: rtID2}},
					Roles:    node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       1,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			false,
		},
		{
			"executor: not enough eligible nodes",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID: nodeID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID: nodeID3,
					Runtimes: []*node.Runtime{
						{ID: rtID2}, // Different runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			false,
		},
		{
			"executor: enough eligible nodes",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID: nodeID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID: nodeID3,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			true,
		},
		{
			"executor: satisfied min pool size constraint",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID: nodeID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID: nodeID3,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
					scheduler.KindComputeExecutor: {
						scheduler.RoleWorker: {
							MinPoolSize: &registry.MinPoolSizeConstraint{
								Limit: 2,
							},
						},
					},
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			true,
		},
		{
			"executor: unsatisfied min pool size constraint",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID: nodeID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID: nodeID3,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
					scheduler.KindComputeExecutor: {
						scheduler.RoleWorker: {
							MinPoolSize: &registry.MinPoolSizeConstraint{
								Limit: 3,
							},
						},
					},
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			false,
		},
		{
			"executor: unsatisfied validator set constraint",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID: nodeID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID: nodeID3,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
					scheduler.KindComputeExecutor: {
						scheduler.RoleWorker: {
							ValidatorSet: &registry.ValidatorSetConstraint{},
						},
					},
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			false,
		},
		{
			"executor: satisfied validator set constraint",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID:       nodeID1,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID:       nodeID3,
					EntityID: entityID2,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{
				staking.NewAddress(entityID1): true,
				staking.NewAddress(entityID2): true,
			},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
					scheduler.KindComputeExecutor: {
						scheduler.RoleWorker: {
							ValidatorSet: &registry.ValidatorSetConstraint{},
						},
					},
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			true,
		},
		{
			"executor: unsatisfied max nodes per entity constraint",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID:       nodeID1,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID:       nodeID3,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
					scheduler.KindComputeExecutor: {
						scheduler.RoleWorker: {
							MaxNodes: &registry.MaxNodesConstraint{
								Limit: 1,
							},
						},
					},
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			false,
		},
		{
			"executor: satisfied max nodes per entity constraint",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID:       nodeID1,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID:       nodeID3,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
					scheduler.KindComputeExecutor: {
						scheduler.RoleWorker: {
							MaxNodes: &registry.MaxNodesConstraint{
								Limit: 2,
							},
						},
					},
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			true,
		},
		{
			"executor: frozen nodes are ineligible",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID:       nodeID1,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID:       nodeID3,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{
				nodeID1: {
					FreezeEndTime: 42, // Frozen.
				},
			},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			false,
		},
		{
			"executor: suspended nodes are ineligible",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID:       nodeID1,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID:       nodeID3,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{
				nodeID1: {
					Faults: map[common.Namespace]*registry.Fault{
						rtID1: {
							SuspendedUntil: 5, // Suspended (current epoch is 1).
						},
					},
				},
			},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			false,
		},
		{
			"executor: unsuspended nodes are eligible again",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID:       nodeID1,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID:       nodeID3,
					EntityID: entityID1,
					Runtimes: []*node.Runtime{
						{ID: rtID1}, // Matching runtime ID.
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{
				nodeID1: {
					Faults: map[common.Namespace]*registry.Fault{
						rtID1: {
							SuspendedUntil: 1, // Not suspended (current epoch is 1).
						},
					},
				},
			},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{},
				},
			},
			true,
		},
		{
			"executor: not enough eligible nodes, incorrect version",
			scheduler.KindComputeExecutor,
			[]*node.Node{
				{
					ID: nodeID1,
					Runtimes: []*node.Runtime{
						{
							ID: rtID1, // Matching runtime ID.
							Version: version.Version{
								Major: 1,
								Minor: 0,
								Patch: 1,
							},
						},
					},
					Roles: node.RoleComputeWorker,
				},
				{
					ID:       nodeID2,
					Runtimes: []*node.Runtime{},  // No runtimes.
					Roles:    node.RoleValidator, // Validator.
				},
				{
					ID: nodeID3,
					Runtimes: []*node.Runtime{
						{
							ID: rtID1, // Matching runtime ID.
							Version: version.Version{
								Major: 1,
								Minor: 0,
								Patch: 0,
							},
						},
					},
					Roles: node.RoleComputeWorker,
				},
			},
			map[signature.PublicKey]*registry.NodeStatus{},
			map[staking.Address]bool{},
			registry.Runtime{
				ID:   rtID1,
				Kind: registry.KindCompute,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 0,
				},
				Deployments: []*registry.VersionInfo{
					{
						Version: version.Version{
							Major: 1,
							Minor: 0,
							Patch: 0,
						},
					},
				},
			},
			false,
		},
	} {
		var nodes []*nodeWithStatus
		for _, node := range tc.nodes {
			status, ok := tc.nodeStatuses[node.ID]
			if !ok {
				status = &registry.NodeStatus{}
			}

			nodes = append(nodes, &nodeWithStatus{node, status})
		}

		err := app.electCommittee(
			ctx,
			epoch,
			schedulerParameters,
			beaconState,
			beaconParameters,
			registryParameters,
			nil,
			make(map[staking.Address]bool),
			tc.validatorEntities,
			&tc.rt,
			nodes,
			tc.kind,
		)
		require.NoError(err, "committee election should not fail")

		c, err := schedulerState.Committee(ctx, tc.kind, tc.rt.ID)
		require.NoError(err, "Committee")
		if !tc.shouldElect {
			require.Nil(c, "Committee should not have been elected (%s)", tc.msg)
			continue
		}

		require.NotNil(c, "Committee should have been elected (%s)", tc.msg)
	}
}
