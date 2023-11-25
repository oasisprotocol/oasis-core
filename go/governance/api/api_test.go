package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func TestValidateBasic(t *testing.T) {
	for _, tc := range []struct {
		msg       string
		p         *ProposalContent
		shouldErr bool
	}{
		{
			msg:       "empty proposal content should fail",
			p:         &ProposalContent{},
			shouldErr: true,
		},
		{
			msg: "only one of Upgrade/CancelUpgrade fields should be set",
			p: &ProposalContent{
				Upgrade:       &UpgradeProposal{},
				CancelUpgrade: &CancelUpgradeProposal{},
			},
			shouldErr: true,
		},
		{
			msg: "upgrade with invalid proposal conent should fail",
			p: &ProposalContent{
				Upgrade: &UpgradeProposal{},
			},
			shouldErr: true,
		},
		{
			msg: "upgrade with valid proposal conent should not fail",
			p: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: upgrade.Descriptor{
						Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
						Handler:   "api_test_handler",
						Target:    version.Versions,
						Epoch:     42,
					},
				},
			},
			shouldErr: false,
		},
		{
			msg: "cancel upgrade proposal content should not fail",
			p: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{},
			},
			shouldErr: false,
		},
	} {
		err := tc.p.ValidateBasic()
		if tc.shouldErr {
			require.NotNil(t, err, tc.msg)
			continue
		}
		require.Nil(t, err, tc.msg)
	}
}

func TestProposalContentEquals(t *testing.T) {
	for _, tc := range []struct {
		msg    string
		p1     *ProposalContent
		p2     *ProposalContent
		equals bool
	}{
		{
			msg: "upgrade proposals should be equal",
			p1: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: upgrade.Descriptor{Handler: "test"},
				},
			},
			p2: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: upgrade.Descriptor{Handler: "test"},
				},
			},
			equals: true,
		},
		{
			msg: "upgrade proposals should not be equal",
			p1: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: upgrade.Descriptor{Handler: "test"},
				},
			},
			p2: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: upgrade.Descriptor{Handler: "test2"},
				},
			},
			equals: false,
		},
		{
			msg: "cancel upgrade and upgrade proposal should not be equal",
			p1: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: upgrade.Descriptor{Handler: "test"},
				},
			},
			p2: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{ProposalID: 1},
			},
			equals: false,
		},
		{
			msg: "cancel upgrade proposals should be equal",
			p1: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{ProposalID: 42},
			},
			p2: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{ProposalID: 42},
			},
			equals: true,
		},
		{
			msg: "cancel upgrade proposals should not be equal",
			p1: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{ProposalID: 42},
			},
			p2: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{ProposalID: 24},
			},
			equals: false,
		},
	} {
		require.Equal(t, tc.equals, tc.p1.Equals(tc.p2), tc.msg)
	}
}

func TestProposalContentPrettyPrint(t *testing.T) {
	for _, tc := range []struct {
		expRegex string
		p        *ProposalContent
	}{
		{
			expRegex: "^Upgrade:",
			p: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: upgrade.Descriptor{Handler: "test"},
				},
			},
		},
		{
			expRegex: "^Cancel Upgrade:",
			p: &ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{ProposalID: 42},
			},
		},
		{
			expRegex: "",
			p:        &ProposalContent{},
		},
		{
			expRegex: "^Change Parameters:",
			p: &ProposalContent{
				ChangeParameters: &ChangeParametersProposal{
					Module: "test-module",
					Changes: cbor.Marshal(map[string]string{
						"test-parameter": "test-value",
					}),
				},
			},
		},
	} {
		var actualPrettyPrint bytes.Buffer
		tc.p.PrettyPrint(context.Background(), "", &actualPrettyPrint)
		require.Regexp(t, tc.expRegex, actualPrettyPrint.String(),
			"pretty printing proposal content didn't return the expected result",
		)
	}
}

func TestProposalVoteSerialization(t *testing.T) {
	require := require.New(t)

	// NOTE: These cases should be synced with tests in runtime/src/consensus/governance.rs.
	for _, tc := range []struct {
		vote           ProposalVote
		expectedBase64 string
	}{
		{ProposalVote{ID: 11, Vote: VoteYes}, "omJpZAtkdm90ZQE="},
		{ProposalVote{ID: 12, Vote: VoteNo}, "omJpZAxkdm90ZQI="},
		{ProposalVote{ID: 13, Vote: VoteAbstain}, "omJpZA1kdm90ZQM="},
	} {
		enc := cbor.Marshal(tc.vote)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec ProposalVote
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.vote, dec, "Proposal vote serialization should round-trip")
	}
}

func TestProposalContentSerialization(t *testing.T) {
	require := require.New(t)

	votingPeriod := beacon.EpochTime(123)

	// NOTE: These cases should be synced with tests in runtime/src/consensus/governance.rs.
	for _, tc := range []struct {
		content        ProposalContent
		expectedBase64 string
	}{
		{
			ProposalContent{
				CancelUpgrade: &CancelUpgradeProposal{ProposalID: 42},
			},
			"oW5jYW5jZWxfdXBncmFkZaFrcHJvcG9zYWxfaWQYKg==",
		},
		{
			ProposalContent{
				Upgrade: &UpgradeProposal{upgrade.Descriptor{
					Versioned: cbor.NewVersioned(2),
					Handler:   "test-handler",
					Target: version.ProtocolVersions{
						ConsensusProtocol:        version.FromU64(123),
						RuntimeHostProtocol:      version.FromU64(456),
						RuntimeCommitteeProtocol: version.FromU64(789),
					},
					Epoch: 42,
				}},
			}, "oWd1cGdyYWRlpGF2AmVlcG9jaBgqZnRhcmdldKNyY29uc2Vuc3VzX3Byb3RvY29soWVwYXRjaBh7dXJ1bnRpbWVfaG9zdF9wcm90b2NvbKFlcGF0Y2gZAch4GnJ1bnRpbWVfY29tbWl0dGVlX3Byb3RvY29soWVwYXRjaBkDFWdoYW5kbGVybHRlc3QtaGFuZGxlcg==",
		},
		{
			ProposalContent{
				ChangeParameters: &ChangeParametersProposal{
					Module: "test-module",
					Changes: cbor.Marshal(ConsensusParameterChanges{
						VotingPeriod: &votingPeriod,
					}),
				},
			}, "oXFjaGFuZ2VfcGFyYW1ldGVyc6JmbW9kdWxla3Rlc3QtbW9kdWxlZ2NoYW5nZXOhbXZvdGluZ19wZXJpb2QYew==",
		},
	} {
		enc := cbor.Marshal(tc.content)
		require.Equal(tc.expectedBase64, base64.StdEncoding.EncodeToString(enc), "serialization should match")

		var dec ProposalContent
		err := cbor.Unmarshal(enc, &dec)
		require.NoError(err, "Unmarshal")
		require.EqualValues(tc.content, dec, "Proposal content serialization should round-trip")
	}
}
