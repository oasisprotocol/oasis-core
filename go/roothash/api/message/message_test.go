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
		{[]Message{{Registry: &RegistryMessage{UpdateRuntime: &registry.Runtime{
			AdmissionPolicy: registry.RuntimeAdmissionPolicy{
				AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
			},
		}}}}, "939029b474d88441515b722f79aa6689195199895fbad7827f711956306c4614"},
		{[]Message{{Registry: &RegistryMessage{UpdateRuntime: rt}}}, "7afcd28fd8303ba3ef4b3342201e64149b00139be56afc0fb48b549c1a3a6b48"},
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
			MinPoolSize:       8, // GroupSize + GroupBackupSize
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			Algorithm:         registry.TxnSchedulerSimple,
			BatchFlushTimeout: 20 * time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1024,
			ProposerTimeout:   5,
		},
		Storage: registry.StorageParameters{
			GroupSize:               3,
			MinWriteReplication:     3,
			MaxApplyWriteLogEntries: 100000,
			MaxApplyOps:             2,
			MinPoolSize:             3,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			EntityWhitelist: &registry.EntityWhitelistRuntimeAdmissionPolicy{
				Entities: map[signature.PublicKey]registry.EntityWhitelistConfig{
					ent.ID: {
						MaxNodes: map[node.RolesMask]uint16{
							node.RoleComputeWorker: 2,
							node.RoleStorageWorker: 4,
						},
					},
				},
			},
		},
		Staking: registry.RuntimeStakingParameters{
			Thresholds: map[staking.ThresholdKind]quantity.Quantity{
				staking.KindNodeCompute: q,
				staking.KindNodeStorage: q,
			},
		},
		GovernanceModel: registry.GovernanceEntity,
	}
	rt.Genesis.StateRoot.Empty()

	return rt
}
