package api

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

func TestValidateBasic(t *testing.T) {
	hh, err := api.OwnHash()
	require.NoError(t, err, "OwnHash()")
	h := hex.EncodeToString(hh[:])
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
					Descriptor: api.Descriptor{
						Method:     api.UpgradeMethodInternal,
						Epoch:      42,
						Identifier: h,
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
					Descriptor: api.Descriptor{Name: "test"},
				},
			},
			p2: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{Name: "test"},
				},
			},
			equals: true,
		},
		{
			msg: "upgrade proposals should not be equal",
			p1: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{Name: "test"},
				},
			},
			p2: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{Name: "test2"},
				},
			},
			equals: false,
		},
		{
			msg: "cancel upgrade and upgrade proposal should not be equal",
			p1: &ProposalContent{
				Upgrade: &UpgradeProposal{
					Descriptor: api.Descriptor{Name: "test"},
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
