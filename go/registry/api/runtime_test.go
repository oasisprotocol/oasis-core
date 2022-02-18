package api

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
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

	// NOTE: These cases should be synced with tests in runtime/src/consensus/staking.rs.
	for _, tc := range []struct {
		rr             Runtime
		expectedBase64 string
	}{
		{Runtime{
			// Note: at least one runtime addmisison policy should always be set.
			AdmissionPolicy: RuntimeAdmissionPolicy{
				AnyNode: &AnyNodeRuntimeAdmissionPolicy{},
			},
		}, "rGF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBodmVyc2lvbnOhZ3ZlcnNpb26gaWVudGl0eV9pZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsdGVlX2hhcmR3YXJlAG10eG5fc2NoZWR1bGVypG5tYXhfYmF0Y2hfc2l6ZQBzYmF0Y2hfZmx1c2hfdGltZW91dAB0bWF4X2JhdGNoX3NpemVfYnl0ZXMAdXByb3Bvc2VfYmF0Y2hfdGltZW91dABwYWRtaXNzaW9uX3BvbGljeaFoYW55X25vZGWgcGdvdmVybmFuY2VfbW9kZWwA"},
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
		}, "rGF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0b3JhZ2Wjc2NoZWNrcG9pbnRfaW50ZXJ2YWwAc2NoZWNrcG9pbnRfbnVtX2tlcHQAdWNoZWNrcG9pbnRfY2h1bmtfc2l6ZQBoZXhlY3V0b3Klamdyb3VwX3NpemUAbG1heF9tZXNzYWdlcwBtcm91bmRfdGltZW91dABxZ3JvdXBfYmFja3VwX3NpemUAcmFsbG93ZWRfc3RyYWdnbGVycwBodmVyc2lvbnOhZ3ZlcnNpb26gaWVudGl0eV9pZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsdGVlX2hhcmR3YXJlAG10eG5fc2NoZWR1bGVypG5tYXhfYmF0Y2hfc2l6ZQBzYmF0Y2hfZmx1c2hfdGltZW91dAB0bWF4X2JhdGNoX3NpemVfYnl0ZXMAdXByb3Bvc2VfYmF0Y2hfdGltZW91dABwYWRtaXNzaW9uX3BvbGljeaFoYW55X25vZGWgcGdvdmVybmFuY2VfbW9kZWwA"},
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
		}, "rWF2AGJpZFggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABka2luZABnZ2VuZXNpc6Jlcm91bmQAanN0YXRlX3Jvb3RYIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ3N0YWtpbmehcnJld2FyZF9iYWRfcmVzdWx0cwpnc3RvcmFnZaNzY2hlY2twb2ludF9pbnRlcnZhbABzY2hlY2twb2ludF9udW1fa2VwdAB1Y2hlY2twb2ludF9jaHVua19zaXplAGhleGVjdXRvcqVqZ3JvdXBfc2l6ZQBsbWF4X21lc3NhZ2VzAG1yb3VuZF90aW1lb3V0AHFncm91cF9iYWNrdXBfc2l6ZQByYWxsb3dlZF9zdHJhZ2dsZXJzAGh2ZXJzaW9uc6FndmVyc2lvbqBpZW50aXR5X2lkWCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGx0ZWVfaGFyZHdhcmUAbXR4bl9zY2hlZHVsZXKkbm1heF9iYXRjaF9zaXplAHNiYXRjaF9mbHVzaF90aW1lb3V0AHRtYXhfYmF0Y2hfc2l6ZV9ieXRlcwB1cHJvcG9zZV9iYXRjaF90aW1lb3V0AHBhZG1pc3Npb25fcG9saWN5oWhhbnlfbm9kZaBwZ292ZXJuYW5jZV9tb2RlbAA="},
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
			Version: VersionInfo{
				Version: version.Version{
					Major: 44,
					Minor: 0,
					Patch: 1,
				},
				TEE: []byte("version tee"),
			},
			KeyManager: &keymanagerID,
			Executor: ExecutorParameters{
				GroupSize:                  9,
				GroupBackupSize:            8,
				AllowedStragglers:          7,
				RoundTimeout:               6,
				MaxMessages:                5,
				MinLiveRoundsPercent:       4,
				MinLiveRoundsForEvaluation: 3,
				MaxLivenessFailures:        2,
			},
			TxnScheduler: TxnSchedulerParameters{
				BatchFlushTimeout: 1 * time.Second,
				MaxBatchSize:      10_000,
				MaxBatchSizeBytes: 10_000_000,
				MaxInMessages:     32,
				ProposerTimeout:   1,
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
		}, "r2F2GCpiaWRYIIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZGtpbmQCZ2dlbmVzaXOiZXJvdW5kGCtqc3RhdGVfcm9vdFggseUhAZ+3vd413IH+55BlYQy937jvXCXihJg2aBkqbQ1nc3Rha2luZ6FycmV3YXJkX2JhZF9yZXN1bHRzCmdzdG9yYWdlo3NjaGVja3BvaW50X2ludGVydmFsGCFzY2hlY2twb2ludF9udW1fa2VwdAZ1Y2hlY2twb2ludF9jaHVua19zaXplGGVoZXhlY3V0b3Koamdyb3VwX3NpemUJbG1heF9tZXNzYWdlcwVtcm91bmRfdGltZW91dAZxZ3JvdXBfYmFja3VwX3NpemUIcmFsbG93ZWRfc3RyYWdnbGVycwdybWF4X2xpdmVuZXNzX2ZhaWxzAnRtaW5fbGl2ZV9yb3VuZHNfZXZhbAN3bWluX2xpdmVfcm91bmRzX3BlcmNlbnQEaHZlcnNpb25zomN0ZWVLdmVyc2lvbiB0ZWVndmVyc2lvbqJlbWFqb3IYLGVwYXRjaAFpZW50aXR5X2lkWCASNFZ4kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGtjb25zdHJhaW50c6EBoQGjaW1heF9ub2Rlc6FlbGltaXQKbW1pbl9wb29sX3NpemWhZWxpbWl0BW12YWxpZGF0b3Jfc2V0oGtrZXlfbWFuYWdlclgggAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFsdGVlX2hhcmR3YXJlAW10eG5fc2NoZWR1bGVypW5tYXhfYmF0Y2hfc2l6ZRknEG9tYXhfaW5fbWVzc2FnZXMYIHNiYXRjaF9mbHVzaF90aW1lb3V0GjuaygB0bWF4X2JhdGNoX3NpemVfYnl0ZXMaAJiWgHVwcm9wb3NlX2JhdGNoX3RpbWVvdXQBcGFkbWlzc2lvbl9wb2xpY3mhcGVudGl0eV93aGl0ZWxpc3ShaGVudGl0aWVzoVggEjRWeJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAChaW1heF9ub2Rlc6IBAwQBcGdvdmVybmFuY2VfbW9kZWwD"},
	} {
		enc := cbor.Marshal(tc.rr)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec Runtime
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.rr, dec, "Runtime serialization should round-trip")
	}
}
