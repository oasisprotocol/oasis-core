package message

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestMessageHash(t *testing.T) {
	require := require.New(t)

	rt := newTestRuntime()
	require.NotNil(rt, "newTestRuntime")

	for _, tc := range []struct {
		msgs         []Message
		expectedHash string
	}{
		{nil, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
		{[]Message{}, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
		{[]Message{{Staking: &StakingMessage{Transfer: &staking.Transfer{}}}}, "a6b91f974b34a9192efd12025659a768520d2f04e1dae9839677456412cdb2be"},
		{[]Message{{Staking: &StakingMessage{Withdraw: &staking.Withdraw{}}}}, "069b0fda76d804e3fd65d4bbd875c646f15798fb573ac613100df67f5ba4c3fd"},
		{[]Message{{Staking: &StakingMessage{AddEscrow: &staking.Escrow{}}}}, "65049870b9dae657390e44065df0c78176816876e67b96dac7791ee6a1aa42e2"},
		{[]Message{{Staking: &StakingMessage{ReclaimEscrow: &staking.ReclaimEscrow{}}}}, "c78547eae2f104268e49827cbe624cf2b350ee59e8d693dec0673a70a4664a2e"},
		{[]Message{{Registry: &RegistryMessage{UpdateRuntime: &registry.Runtime{
			AdmissionPolicy: registry.RuntimeAdmissionPolicy{
				AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
			},
		}}}}, "ac8ff938607f234f0db60dc2e81897f50c3918cc51998c633a0f3f2b98374db1"},
		{[]Message{{Registry: &RegistryMessage{UpdateRuntime: rt}}}, "67da1da17b12c398d4dec165480df73c244740f8fb876f59a76cd29e30056b6d"},
	} {
		var h hash.Hash
		err := h.UnmarshalHex(tc.expectedHash)
		require.NoError(err, "UnmarshalHex")

		require.Equal(h.String(), MessagesHash(tc.msgs).String(), "MessageHash must return the expected hash")
	}
}

func TestMessageValidateBasic(t *testing.T) {
	require := require.New(t)

	for _, tc := range []struct {
		name  string
		msg   Message
		valid bool
	}{
		{"NoFieldsSet", Message{}, false},
		{"StakingNoFieldsSet", Message{Staking: &StakingMessage{}}, false},
		{"StakingMultipleFieldsSet", Message{Staking: &StakingMessage{Transfer: &staking.Transfer{}, Withdraw: &staking.Withdraw{}}}, false},
		{"StakingAllFieldsSet", Message{Staking: &StakingMessage{Transfer: &staking.Transfer{}, Withdraw: &staking.Withdraw{}, AddEscrow: &staking.Escrow{}, ReclaimEscrow: &staking.ReclaimEscrow{}}}, false},
		{"ValidStaking", Message{Staking: &StakingMessage{Transfer: &staking.Transfer{}}}, true},
		{"RegistryNoFieldsSet", Message{Registry: &RegistryMessage{}}, false},
		{"RegistryInvalid", Message{Registry: &RegistryMessage{UpdateRuntime: nil}}, false},
		{"ValidRegistry", Message{Registry: &RegistryMessage{UpdateRuntime: &registry.Runtime{}}}, true},
	} {
		err := tc.msg.ValidateBasic()
		if tc.valid {
			require.NoError(err, tc.name)
		} else {
			require.Error(err, tc.name)
		}
	}
}

func newTestRuntime() *registry.Runtime {
	ent, _, _ := entity.TestEntity()

	// Use an ID of all-zeroes, so it's easier to generate on the Rust side too.
	var id common.Namespace

	var q quantity.Quantity
	_ = q.FromUint64(1000)

	rt := &registry.Runtime{
		Versioned: cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:        id,
		EntityID:  ent.ID,
		Kind:      registry.KindCompute,
		Executor: registry.ExecutorParameters{
			GroupSize:         3,
			GroupBackupSize:   5,
			AllowedStragglers: 1,
			RoundTimeout:      10,
			MaxMessages:       32,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			BatchFlushTimeout: 20 * time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1024,
			ProposerTimeout:   5,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			EntityWhitelist: &registry.EntityWhitelistRuntimeAdmissionPolicy{
				Entities: map[signature.PublicKey]registry.EntityWhitelistConfig{
					ent.ID: {
						MaxNodes: map[node.RolesMask]uint16{
							node.RoleComputeWorker: 2,
						},
					},
				},
			},
		},
		Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
			scheduler.KindComputeExecutor: {
				scheduler.RoleWorker: {
					MinPoolSize: &registry.MinPoolSizeConstraint{
						Limit: 1,
					},
					ValidatorSet: &registry.ValidatorSetConstraint{},
				},
				scheduler.RoleBackupWorker: {
					MinPoolSize: &registry.MinPoolSizeConstraint{
						Limit: 2,
					},
				},
			},
		},
		Staking: registry.RuntimeStakingParameters{
			Thresholds: map[staking.ThresholdKind]quantity.Quantity{
				staking.KindNodeCompute: q,
			},
		},
		GovernanceModel: registry.GovernanceEntity,
		Deployments:     []*registry.VersionInfo{{}},
	}
	rt.Genesis.StateRoot.Empty()

	return rt
}
