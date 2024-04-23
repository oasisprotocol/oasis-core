package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func createTestVault() *Vault {
	return &Vault{
		AdminAuthority: Authority{
			Addresses: []staking.Address{
				testAddrA,
				testAddrB,
			},
			Threshold: 2,
		},
		SuspendAuthority: Authority{
			Addresses: []staking.Address{
				testAddrB,
				testAddrC,
				testAddrD,
			},
			Threshold: 1,
		},
	}
}

func TestActionBasic(t *testing.T) {
	require := require.New(t)

	action := Action{}
	err := action.Validate(&ConsensusParameters{})
	require.Error(err, "Validate should fail on empty action")

	action = Action{
		Suspend: &ActionSuspend{},
		Resume:  &ActionResume{},
	}
	err = action.Validate(&ConsensusParameters{})
	require.Error(err, "Validate should fail on action with multiple fields set")

	actionA := Action{
		Suspend: &ActionSuspend{},
	}
	actionB := Action{
		Resume: &ActionResume{},
	}
	actionC := Action{
		Resume: &ActionResume{},
	}
	require.False(actionA.Equal(&actionB), "different actions should not be Equal")
	require.True(actionB.Equal(&actionC), "same actions should be Equal")
}

func TestActionSuspend(t *testing.T) {
	require := require.New(t)

	vault := createTestVault()
	action := Action{
		Suspend: &ActionSuspend{},
	}
	require.EqualValues(
		action.Authorities(vault),
		[]*Authority{&vault.AdminAuthority, &vault.SuspendAuthority},
		"suspend should require admin or suspend authority",
	)
}

func TestActionResume(t *testing.T) {
	require := require.New(t)

	vault := createTestVault()
	action := Action{
		Resume: &ActionResume{},
	}
	require.EqualValues(
		action.Authorities(vault),
		[]*Authority{&vault.AdminAuthority, &vault.SuspendAuthority},
		"resume should require admin or suspend authority",
	)
}

func TestActionExecuteMessage(t *testing.T) {
	require := require.New(t)

	vault := createTestVault()
	action := Action{
		ExecuteMessage: &ActionExecuteMessage{
			Method: "foo",
		},
	}
	require.EqualValues(
		action.Authorities(vault),
		[]*Authority{&vault.AdminAuthority},
		"execute message should require admin authority",
	)
}

func TestActionUpdateWithdrawPolicy(t *testing.T) {
	require := require.New(t)

	vault := createTestVault()
	action := Action{
		UpdateWithdrawPolicy: &ActionUpdateWithdrawPolicy{
			Address: testAddrA,
			Policy: WithdrawPolicy{
				LimitAmount:   *quantity.NewFromUint64(1000),
				LimitInterval: 24 * 600,
			},
		},
	}
	require.EqualValues(
		action.Authorities(vault),
		[]*Authority{&vault.AdminAuthority},
		"update withdraw policy should require admin authority",
	)
}

func TestActionUpdateAuthority(t *testing.T) {
	require := require.New(t)

	vault := createTestVault()
	action := Action{
		UpdateAuthority: &ActionUpdateAuthority{
			AdminAuthority: &Authority{
				Addresses: []staking.Address{
					testAddrA,
				},
				Threshold: 1,
			},
		},
	}
	require.EqualValues(
		action.Authorities(vault),
		[]*Authority{&vault.AdminAuthority},
		"update authority should require admin authority",
	)

	newVault := createTestVault()
	action.UpdateAuthority.Apply(newVault)
	require.EqualValues(newVault.AdminAuthority, *action.UpdateAuthority.AdminAuthority)
	require.EqualValues(newVault.SuspendAuthority, vault.SuspendAuthority)

	action = Action{
		UpdateAuthority: &ActionUpdateAuthority{
			SuspendAuthority: &Authority{
				Addresses: []staking.Address{
					testAddrA,
				},
				Threshold: 1,
			},
		},
	}

	action.UpdateAuthority.Apply(newVault)
	require.EqualValues(newVault.SuspendAuthority, *action.UpdateAuthority.SuspendAuthority)
}
