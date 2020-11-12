package message

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestMessageHash(t *testing.T) {
	require := require.New(t)

	for _, tc := range []struct {
		msgs         []Message
		expectedHash string
	}{
		{nil, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
		{[]Message{}, "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"},
		{[]Message{{Noop: &NoopMessage{}}}, "c8b55f87109e30fe2ba57507ffc0e96e40df7c0d24dfef82a858632f5f8420f1"},
		{[]Message{{Staking: &StakingMessage{Transfer: &staking.Transfer{}}}}, "a6b91f974b34a9192efd12025659a768520d2f04e1dae9839677456412cdb2be"},
		{[]Message{{Staking: &StakingMessage{Withdraw: &staking.Withdraw{}}}}, "069b0fda76d804e3fd65d4bbd875c646f15798fb573ac613100df67f5ba4c3fd"},
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
		{"ValidNoop", Message{Noop: &NoopMessage{}}, true},
		{"StakingNoFieldsSet", Message{Staking: &StakingMessage{}}, false},
		{"StakingMultipleFieldsSet", Message{Staking: &StakingMessage{Transfer: &staking.Transfer{}, Withdraw: &staking.Withdraw{}}}, false},
		{"ValidStaking", Message{Staking: &StakingMessage{Transfer: &staking.Transfer{}}}, true},
	} {
		err := tc.msg.ValidateBasic()
		if tc.valid {
			require.NoError(err, tc.name)
		} else {
			require.Error(err, tc.name)
		}
	}
}
