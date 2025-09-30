package api

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

func TestRuntimeSerialization(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	require.NoError(runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000"), "runtime id")
	var keymanagerID common.Namespace
	require.NoError(keymanagerID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001"), "keymanager id")
	var h hash.Hash
	h.FromBytes([]byte("stateroot hash"))

	// NOTE: These cases should be synced with tests in runtime/src/consensus/registry.rs.
	for _, tc := range []struct {
		rr             Runtime
		expectedBase64 string
	}{
		{Runtime{
			// Note: at least one runtime addmisison policy should always be set.
			AdmissionPolicy: RuntimeAdmissionPolicy{
				AnyNode: &AnyNodeRuntimeAdmissionPolicy{},
			},
		}, "qmF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGx0ZWVfaGFyZHdhcmUAcGFkbWlzc2lvbl9wb2xpY3mhaGFueV9ub2RloHBnb3Zlcm5hbmNlX21vZGVsAA=="},
		{Runtime{
			AdmissionPolicy: RuntimeAdmissionPolicy{
				AnyNode: &AnyNodeRuntimeAdmissionPolicy{},
			},
			Staking: RuntimeStakingParameters{
				Thresholds:                           nil,
				Slashing:                             nil,
				RewardSlashBadResultsRuntimePercent:  0,
				RewardSlashEquvocationRuntimePercent: 0,
				MinInMessageFee:                      quantity.Quantity{},
			},
		}, "qmF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGx0ZWVfaGFyZHdhcmUAcGFkbWlzc2lvbl9wb2xpY3mhaGFueV9ub2RloHBnb3Zlcm5hbmNlX21vZGVsAA=="},
		{Runtime{
			AdmissionPolicy: RuntimeAdmissionPolicy{
				AnyNode: &AnyNodeRuntimeAdmissionPolicy{},
			},
			Staking: RuntimeStakingParameters{
				Thresholds:                           nil,
				Slashing:                             nil,
				RewardSlashBadResultsRuntimePercent:  10,
				RewardSlashEquvocationRuntimePercent: 0,
				MinInMessageFee:                      quantity.Quantity{},
			},
		}, "q2F2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0YWtpbmehcnJld2FyZF9iYWRfcmVzdWx0cwpnc3RvcmFnZaNzY2hlY2twb2ludF9pbnRlcnZhbABzY2hlY2twb2ludF9udW1fa2VwdAB1Y2hlY2twb2ludF9jaHVua19zaXplAGhleGVjdXRvcqVqZ3JvdXBfc2l6ZQBsbWF4X21lc3NhZ2VzAG1yb3VuZF90aW1lb3V0AHFncm91cF9iYWNrdXBfc2l6ZQByYWxsb3dlZF9zdHJhZ2dsZXJzAGllbnRpdHlfaWRYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbHRlZV9oYXJkd2FyZQBwYWRtaXNzaW9uX3BvbGljeaFoYW55X25vZGWgcGdvdmVybmFuY2VfbW9kZWwA"},
		{Runtime{
			Versioned: cbor.NewVersioned(42),
			EntityID:  signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"),
			ID:        runtimeID,
			Genesis: RuntimeGenesis{
				Round:     43,
				StateRoot: h,
			},
			Kind:        KindKeyManager,
			TEEHardware: node.TEEHardwareIntelSGX,
			Deployments: []*VersionInfo{
				{
					Version: version.Version{
						Major: 44,
						Minor: 0,
						Patch: 1,
					},
					TEE:            []byte("version tee"),
					BundleChecksum: bytes.Repeat([]byte{0x01}, 32),
				},
			},
			KeyManager: &keymanagerID,
			Executor: ExecutorParameters{
				GroupSize:                  9,
				GroupBackupSize:            8,
				AllowedStragglers:          7,
				RoundTimeout:               6,
				MaxMessages:                5,
				MinLiveRoundsPercent:       4,
				MaxMissedProposalsPercent:  3,
				MinLiveRoundsForEvaluation: 2,
				MaxLivenessFailures:        1,
			},
			TxnScheduler: TxnSchedulerParameters{
				BatchFlushTimeout: time.Second,
				MaxBatchSize:      10_000,
				MaxBatchSizeBytes: 10_000_000,
				MaxInMessages:     32,
				ProposerTimeout:   2 * time.Second,
			},
			Storage: StorageParameters{
				CheckpointInterval:  33,
				CheckpointNumKept:   6,
				CheckpointChunkSize: 101,
			},
			AdmissionPolicy: RuntimeAdmissionPolicy{
				EntityWhitelist: &EntityWhitelistRuntimeAdmissionPolicy{
					Entities: map[signature.PublicKey]EntityWhitelistConfig{
						signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"): {
							MaxNodes: map[node.RolesMask]uint16{
								node.RoleComputeWorker: 3,
								node.RoleKeyManager:    1,
							},
						},
					},
				},
			},
			Constraints: map[api.CommitteeKind]map[api.Role]SchedulingConstraints{
				api.KindComputeExecutor: {
					api.RoleWorker: {
						MaxNodes: &MaxNodesConstraint{
							Limit: 10,
						},
						MinPoolSize: &MinPoolSizeConstraint{
							Limit: 5,
						},
						ValidatorSet: &ValidatorSetConstraint{},
					},
				},
			},
			GovernanceModel: GovernanceConsensus,
			Staking: RuntimeStakingParameters{
				Thresholds:                           nil,
				Slashing:                             nil,
				RewardSlashBadResultsRuntimePercent:  10,
				RewardSlashEquvocationRuntimePercent: 0,
				MinInMessageFee:                      quantity.Quantity{},
			},
		}, "r2F2GCpiaWRYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZGtpbmQCZ2dlbmVzaXOiZXJvdW5kGCtqc3RhdGVfcm9vdFggseUhAZ+3vd413IH+55BlYQy937jvXCXihJg2aBkqbQ1nc3Rha2luZ6FycmV3YXJkX2JhZF9yZXN1bHRzCmdzdG9yYWdlo3NjaGVja3BvaW50X2ludGVydmFsGCFzY2hlY2twb2ludF9udW1fa2VwdAZ1Y2hlY2twb2ludF9jaHVua19zaXplGGVoZXhlY3V0b3Kpamdyb3VwX3NpemUJbG1heF9tZXNzYWdlcwVtcm91bmRfdGltZW91dAZxZ3JvdXBfYmFja3VwX3NpemUIcmFsbG93ZWRfc3RyYWdnbGVycwdybWF4X2xpdmVuZXNzX2ZhaWxzAXRtaW5fbGl2ZV9yb3VuZHNfZXZhbAJ3bWluX2xpdmVfcm91bmRzX3BlcmNlbnQEeBxtYXhfbWlzc2VkX3Byb3Bvc2Fsc19wZXJjZW50A2llbnRpdHlfaWRYIBI0VniQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa2NvbnN0cmFpbnRzoQGhAaNpbWF4X25vZGVzoWVsaW1pdAptbWluX3Bvb2xfc2l6ZaFlbGltaXQFbXZhbGlkYXRvcl9zZXSga2RlcGxveW1lbnRzgaRjdGVlS3ZlcnNpb24gdGVlZ3ZlcnNpb26iZW1ham9yGCxlcGF0Y2gBanZhbGlkX2Zyb20Ab2J1bmRsZV9jaGVja3N1bVggAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQFra2V5X21hbmFnZXJYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABbHRlZV9oYXJkd2FyZQFtdHhuX3NjaGVkdWxlcqVubWF4X2JhdGNoX3NpemUZJxBvbWF4X2luX21lc3NhZ2VzGCBzYmF0Y2hfZmx1c2hfdGltZW91dBo7msoAdG1heF9iYXRjaF9zaXplX2J5dGVzGgCYloB1cHJvcG9zZV9iYXRjaF90aW1lb3V0Gnc1lABwYWRtaXNzaW9uX3BvbGljeaFwZW50aXR5X3doaXRlbGlzdKFoZW50aXRpZXOhWCASNFZ4kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKFpbWF4X25vZGVzogEDBAFwZ292ZXJuYW5jZV9tb2RlbAM="},
	} {
		enc := cbor.Marshal(tc.rr)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Runtime
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.rr, dec, "Runtime serialization should round-trip")
	}
}

func TestVerifyRuntime(t *testing.T) {
	require := require.New(t)

	var runtimeID common.Namespace
	require.NoError(runtimeID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000"), "runtime id")
	var keymanagerID common.Namespace
	require.NoError(keymanagerID.UnmarshalHex("c000000000000000000000000000000000000000000000000000000000000001"), "keymanager id")
	var h hash.Hash
	h.FromBytes([]byte("stateroot hash"))

	for _, tc := range []struct {
		rr   Runtime
		cpFn func(*ConsensusParameters)
		err  error
		msg  string
	}{
		{
			Runtime{
				Versioned: cbor.NewVersioned(3),
				EntityID:  signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"),
				ID:        runtimeID,
				Genesis: RuntimeGenesis{
					Round:     43,
					StateRoot: h,
				},
				Kind:        KindCompute,
				TEEHardware: node.TEEHardwareInvalid,
				Deployments: []*VersionInfo{
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 1,
						},
					},
				},
				KeyManager: &keymanagerID,
				Executor: ExecutorParameters{
					GroupSize:                  9,
					GroupBackupSize:            8,
					AllowedStragglers:          7,
					RoundTimeout:               6,
					MaxMessages:                5,
					MinLiveRoundsPercent:       4,
					MaxMissedProposalsPercent:  3,
					MinLiveRoundsForEvaluation: 2,
					MaxLivenessFailures:        1,
				},
				TxnScheduler: TxnSchedulerParameters{
					BatchFlushTimeout: time.Second,
					MaxBatchSize:      10_000,
					MaxBatchSizeBytes: 10_000_000,
					MaxInMessages:     32,
					ProposerTimeout:   2 * time.Second,
				},
				Storage: StorageParameters{
					CheckpointInterval:  33,
					CheckpointNumKept:   6,
					CheckpointChunkSize: 1_000_000_000,
				},
				AdmissionPolicy: RuntimeAdmissionPolicy{
					EntityWhitelist: &EntityWhitelistRuntimeAdmissionPolicy{
						Entities: map[signature.PublicKey]EntityWhitelistConfig{
							signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"): {
								MaxNodes: map[node.RolesMask]uint16{
									node.RoleComputeWorker: 3,
									node.RoleKeyManager:    1,
								},
							},
						},
					},
				},
				Constraints: map[api.CommitteeKind]map[api.Role]SchedulingConstraints{
					api.KindComputeExecutor: {
						api.RoleWorker: {
							MaxNodes: &MaxNodesConstraint{
								Limit: 10,
							},
							MinPoolSize: &MinPoolSizeConstraint{
								Limit: 5,
							},
							ValidatorSet: &ValidatorSetConstraint{},
						},
					},
				},
				GovernanceModel: GovernanceConsensus,
				Staking: RuntimeStakingParameters{
					Thresholds:                           nil,
					Slashing:                             nil,
					RewardSlashBadResultsRuntimePercent:  10,
					RewardSlashEquvocationRuntimePercent: 0,
					MinInMessageFee:                      quantity.Quantity{},
				},
			},
			nil,
			nil,
			"valid runtime",
		},
		{
			Runtime{
				Versioned: cbor.NewVersioned(3),
				EntityID:  signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"),
				ID:        runtimeID,
				Genesis: RuntimeGenesis{
					Round:     43,
					StateRoot: h,
				},
				Kind:        KindCompute,
				TEEHardware: node.TEEHardwareInvalid,
				Deployments: []*VersionInfo{
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 1,
						},
					},
					nil,
				},
				KeyManager: &keymanagerID,
				Executor: ExecutorParameters{
					GroupSize:                  9,
					GroupBackupSize:            8,
					AllowedStragglers:          7,
					RoundTimeout:               6,
					MaxMessages:                5,
					MinLiveRoundsPercent:       4,
					MaxMissedProposalsPercent:  3,
					MinLiveRoundsForEvaluation: 2,
					MaxLivenessFailures:        1,
				},
				TxnScheduler: TxnSchedulerParameters{
					BatchFlushTimeout: time.Second,
					MaxBatchSize:      10_000,
					MaxBatchSizeBytes: 10_000_000,
					MaxInMessages:     32,
					ProposerTimeout:   2 * time.Second,
				},
				Storage: StorageParameters{
					CheckpointInterval:  33,
					CheckpointNumKept:   6,
					CheckpointChunkSize: 1_000_000_000,
				},
				AdmissionPolicy: RuntimeAdmissionPolicy{
					EntityWhitelist: &EntityWhitelistRuntimeAdmissionPolicy{
						Entities: map[signature.PublicKey]EntityWhitelistConfig{
							signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"): {
								MaxNodes: map[node.RolesMask]uint16{
									node.RoleComputeWorker: 3,
									node.RoleKeyManager:    1,
								},
							},
						},
					},
				},
				Constraints: map[api.CommitteeKind]map[api.Role]SchedulingConstraints{
					api.KindComputeExecutor: {
						api.RoleWorker: {
							MaxNodes: &MaxNodesConstraint{
								Limit: 10,
							},
							MinPoolSize: &MinPoolSizeConstraint{
								Limit: 5,
							},
							ValidatorSet: &ValidatorSetConstraint{},
						},
					},
				},
				GovernanceModel: GovernanceConsensus,
				Staking: RuntimeStakingParameters{
					Thresholds:                           nil,
					Slashing:                             nil,
					RewardSlashBadResultsRuntimePercent:  10,
					RewardSlashEquvocationRuntimePercent: 0,
					MinInMessageFee:                      quantity.Quantity{},
				},
			},
			nil,
			ErrInvalidArgument,
			"invalid runtime (nil deployment)",
		},
		{
			Runtime{
				Versioned: cbor.NewVersioned(3),
				EntityID:  signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"),
				ID:        runtimeID,
				Genesis: RuntimeGenesis{
					Round:     43,
					StateRoot: h,
				},
				Kind:        KindCompute,
				TEEHardware: node.TEEHardwareInvalid,
				Deployments: []*VersionInfo{
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 1,
						},
						ValidFrom: 0,
					},
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 2,
						},
						ValidFrom: 1,
					},
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 3,
						},
						ValidFrom: 2,
					},
				},
				KeyManager: &keymanagerID,
				Executor: ExecutorParameters{
					GroupSize:                  9,
					GroupBackupSize:            8,
					AllowedStragglers:          7,
					RoundTimeout:               6,
					MaxMessages:                5,
					MinLiveRoundsPercent:       4,
					MaxMissedProposalsPercent:  3,
					MinLiveRoundsForEvaluation: 2,
					MaxLivenessFailures:        1,
				},
				TxnScheduler: TxnSchedulerParameters{
					BatchFlushTimeout: time.Second,
					MaxBatchSize:      10_000,
					MaxBatchSizeBytes: 10_000_000,
					MaxInMessages:     32,
					ProposerTimeout:   2 * time.Second,
				},
				Storage: StorageParameters{
					CheckpointInterval:  33,
					CheckpointNumKept:   6,
					CheckpointChunkSize: 1_000_000_000,
				},
				AdmissionPolicy: RuntimeAdmissionPolicy{
					EntityWhitelist: &EntityWhitelistRuntimeAdmissionPolicy{
						Entities: map[signature.PublicKey]EntityWhitelistConfig{
							signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"): {
								MaxNodes: map[node.RolesMask]uint16{
									node.RoleComputeWorker: 3,
									node.RoleKeyManager:    1,
								},
							},
						},
					},
				},
				Constraints: map[api.CommitteeKind]map[api.Role]SchedulingConstraints{
					api.KindComputeExecutor: {
						api.RoleWorker: {
							MaxNodes: &MaxNodesConstraint{
								Limit: 10,
							},
							MinPoolSize: &MinPoolSizeConstraint{
								Limit: 5,
							},
							ValidatorSet: &ValidatorSetConstraint{},
						},
					},
				},
				GovernanceModel: GovernanceConsensus,
				Staking: RuntimeStakingParameters{
					Thresholds:                           nil,
					Slashing:                             nil,
					RewardSlashBadResultsRuntimePercent:  10,
					RewardSlashEquvocationRuntimePercent: 0,
					MinInMessageFee:                      quantity.Quantity{},
				},
			},
			nil,
			ErrInvalidArgument,
			"invalid runtime (too many deployments)",
		},
		{
			Runtime{
				Versioned: cbor.NewVersioned(3),
				EntityID:  signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"),
				ID:        runtimeID,
				Genesis: RuntimeGenesis{
					Round:     43,
					StateRoot: h,
				},
				Kind:        KindCompute,
				TEEHardware: node.TEEHardwareInvalid,
				Deployments: []*VersionInfo{
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 1,
						},
						ValidFrom: 0,
					},
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 2,
						},
						ValidFrom: 1,
					},
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 3,
						},
						ValidFrom:      2,
						BundleChecksum: []byte{1, 2, 3, 4, 5, 6, 7},
					},
				},
				KeyManager: &keymanagerID,
				Executor: ExecutorParameters{
					GroupSize:                  9,
					GroupBackupSize:            8,
					AllowedStragglers:          7,
					RoundTimeout:               6,
					MaxMessages:                5,
					MinLiveRoundsPercent:       4,
					MaxMissedProposalsPercent:  3,
					MinLiveRoundsForEvaluation: 2,
					MaxLivenessFailures:        1,
				},
				TxnScheduler: TxnSchedulerParameters{
					BatchFlushTimeout: time.Second,
					MaxBatchSize:      10_000,
					MaxBatchSizeBytes: 10_000_000,
					MaxInMessages:     32,
					ProposerTimeout:   2 * time.Second,
				},
				Storage: StorageParameters{
					CheckpointInterval:  33,
					CheckpointNumKept:   6,
					CheckpointChunkSize: 1_000_000_000,
				},
				AdmissionPolicy: RuntimeAdmissionPolicy{
					EntityWhitelist: &EntityWhitelistRuntimeAdmissionPolicy{
						Entities: map[signature.PublicKey]EntityWhitelistConfig{
							signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"): {
								MaxNodes: map[node.RolesMask]uint16{
									node.RoleComputeWorker: 3,
									node.RoleKeyManager:    1,
								},
							},
						},
					},
				},
				Constraints: map[api.CommitteeKind]map[api.Role]SchedulingConstraints{
					api.KindComputeExecutor: {
						api.RoleWorker: {
							MaxNodes: &MaxNodesConstraint{
								Limit: 10,
							},
							MinPoolSize: &MinPoolSizeConstraint{
								Limit: 5,
							},
							ValidatorSet: &ValidatorSetConstraint{},
						},
					},
				},
				GovernanceModel: GovernanceConsensus,
				Staking: RuntimeStakingParameters{
					Thresholds:                           nil,
					Slashing:                             nil,
					RewardSlashBadResultsRuntimePercent:  10,
					RewardSlashEquvocationRuntimePercent: 0,
					MinInMessageFee:                      quantity.Quantity{},
				},
			},
			func(cp *ConsensusParameters) {
				// Increase the maximum number of allowed deployments.
				cp.MaxRuntimeDeployments = 5
			},
			ErrInvalidArgument,
			"invalid runtime (deployment with invalid checkusm)",
		},
		{
			Runtime{
				Versioned: cbor.NewVersioned(3),
				EntityID:  signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"),
				ID:        runtimeID,
				Genesis: RuntimeGenesis{
					Round:     43,
					StateRoot: h,
				},
				Kind:        KindCompute,
				TEEHardware: node.TEEHardwareInvalid,
				Deployments: []*VersionInfo{
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 1,
						},
						ValidFrom: 0,
					},
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 2,
						},
						ValidFrom: 1,
					},
					{
						Version: version.Version{
							Major: 44,
							Minor: 0,
							Patch: 3,
						},
						ValidFrom:      2,
						BundleChecksum: bytes.Repeat([]byte{0x01}, 32),
					},
				},
				KeyManager: &keymanagerID,
				Executor: ExecutorParameters{
					GroupSize:                  9,
					GroupBackupSize:            8,
					AllowedStragglers:          7,
					RoundTimeout:               6,
					MaxMessages:                5,
					MinLiveRoundsPercent:       4,
					MaxMissedProposalsPercent:  3,
					MinLiveRoundsForEvaluation: 2,
					MaxLivenessFailures:        1,
				},
				TxnScheduler: TxnSchedulerParameters{
					BatchFlushTimeout: time.Second,
					MaxBatchSize:      10_000,
					MaxBatchSizeBytes: 10_000_000,
					MaxInMessages:     32,
					ProposerTimeout:   2 * time.Second,
				},
				Storage: StorageParameters{
					CheckpointInterval:  33,
					CheckpointNumKept:   6,
					CheckpointChunkSize: 1_000_000_000,
				},
				AdmissionPolicy: RuntimeAdmissionPolicy{
					EntityWhitelist: &EntityWhitelistRuntimeAdmissionPolicy{
						Entities: map[signature.PublicKey]EntityWhitelistConfig{
							signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000"): {
								MaxNodes: map[node.RolesMask]uint16{
									node.RoleComputeWorker: 3,
									node.RoleKeyManager:    1,
								},
							},
						},
					},
				},
				Constraints: map[api.CommitteeKind]map[api.Role]SchedulingConstraints{
					api.KindComputeExecutor: {
						api.RoleWorker: {
							MaxNodes: &MaxNodesConstraint{
								Limit: 10,
							},
							MinPoolSize: &MinPoolSizeConstraint{
								Limit: 5,
							},
							ValidatorSet: &ValidatorSetConstraint{},
						},
					},
				},
				GovernanceModel: GovernanceConsensus,
				Staking: RuntimeStakingParameters{
					Thresholds:                           nil,
					Slashing:                             nil,
					RewardSlashBadResultsRuntimePercent:  10,
					RewardSlashEquvocationRuntimePercent: 0,
					MinInMessageFee:                      quantity.Quantity{},
				},
			},
			func(cp *ConsensusParameters) {
				// Increase the maximum number of allowed deployments.
				cp.MaxRuntimeDeployments = 5
			},
			nil,
			"valid runtime",
		},
	} {
		cp := ConsensusParameters{
			MaxNodeExpiration: 10,
			EnableRuntimeGovernanceModels: map[RuntimeGovernanceModel]bool{
				GovernanceConsensus: true,
				GovernanceEntity:    true,
				GovernanceRuntime:   true,
			},
		}
		if tc.cpFn != nil {
			tc.cpFn(&cp)
		}

		err := VerifyRuntime(&cp, logging.GetLogger("runtime/tests"), &tc.rr, false, true, beacon.EpochTime(10))
		switch {
		case tc.err == nil:
			require.NoError(err, tc.msg)
		default:
			require.True(errors.Is(err, tc.err), fmt.Sprintf("expected err: '%v', got: '%v', for: %s", tc.err, err, tc.msg))
		}
	}
}

func TestDeployments(t *testing.T) {
	require := require.New(t)

	var rt Runtime
	require.Nil(rt.ActiveDeployment(0))

	rt = Runtime{
		Deployments: []*VersionInfo{
			{
				Version: version.Version{
					Major: 0,
					Minor: 1,
					Patch: 0,
				},
				ValidFrom: 0,
			},
			{
				Version: version.Version{
					Major: 0,
					Minor: 2,
					Patch: 0,
				},
				ValidFrom: 10,
			},
			{
				Version: version.Version{
					Major: 0,
					Minor: 3,
					Patch: 0,
				},
				ValidFrom: 20,
			},
		},
	}

	ad := rt.ActiveDeployment(0)
	require.EqualValues(1, ad.Version.Minor)
	ad = rt.ActiveDeployment(1)
	require.EqualValues(1, ad.Version.Minor)
	ad = rt.ActiveDeployment(9)
	require.EqualValues(1, ad.Version.Minor)
	ad = rt.ActiveDeployment(10)
	require.EqualValues(2, ad.Version.Minor)
	ad = rt.ActiveDeployment(20)
	require.EqualValues(3, ad.Version.Minor)
	ad = rt.ActiveDeployment(50)
	require.EqualValues(3, ad.Version.Minor)
	ad = rt.ActiveDeployment(100)
	require.EqualValues(3, ad.Version.Minor)
	ad = rt.ActiveDeployment(1000)
	require.EqualValues(3, ad.Version.Minor)

	nd := rt.NextDeployment(0)
	require.EqualValues(2, nd.Version.Minor)
	nd = rt.NextDeployment(1)
	require.EqualValues(2, nd.Version.Minor)
	nd = rt.NextDeployment(9)
	require.EqualValues(2, nd.Version.Minor)
	nd = rt.NextDeployment(10)
	require.EqualValues(3, nd.Version.Minor)
	nd = rt.NextDeployment(20)
	require.Nil(nd)
	nd = rt.NextDeployment(50)
	require.Nil(nd)
	nd = rt.NextDeployment(100)
	require.Nil(nd)
	nd = rt.NextDeployment(1000)
	require.Nil(nd)

	ad = rt.DeploymentForVersion(version.Version{
		Major: 0,
		Minor: 1,
		Patch: 0,
	})
	require.EqualValues(0, ad.ValidFrom)

	ad = rt.DeploymentForVersion(version.Version{
		Major: 0,
		Minor: 2,
		Patch: 0,
	})
	require.EqualValues(10, ad.ValidFrom)

	ad = rt.DeploymentForVersion(version.Version{
		Major: 0,
		Minor: 3,
		Patch: 0,
	})
	require.EqualValues(20, ad.ValidFrom)

	ad = rt.DeploymentForVersion(version.Version{
		Major: 0,
		Minor: 99,
		Patch: 0,
	})
	require.Nil(ad)
}
