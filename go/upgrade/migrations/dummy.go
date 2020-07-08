package migrations

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/multisig"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// DummyUpgradeName is the name of the dummy upgrade, for use in the upgrade descriptor.
	DummyUpgradeName = "__e2e-test-valid"

	testSigningSeed = "__e2e-test-migration-entity"
)

var (
	_ Handler = (*dummyMigrationHandler)(nil)

	TestEntity entity.Entity

	entityAccount *multisig.Account
	entityAddress staking.Address
	entitySigner  signature.Signer
)

func init() {
	entitySigner = memory.NewTestSigner(testSigningSeed)
	entityAccount = multisig.NewAccountFromPublicKey(entitySigner.Public())
	entityAddress = staking.NewAddress(entityAccount)

	TestEntity.Versioned.V = entity.LatestEntityDescriptorVersion
	TestEntity.AccountAddress = entityAddress
}

type dummyMigrationHandler struct {
}

func (th *dummyMigrationHandler) StartupUpgrade(ctx *Context) error {
	return nil
}

func (th *dummyMigrationHandler) ConsensusUpgrade(ctx *Context, privateCtx interface{}) error {
	abciCtx := privateCtx.(*abciAPI.Context)
	regState := registryState.NewMutableState(abciCtx.State())
	stakeState := stakingState.NewMutableState(abciCtx.State())

	sigEntity, err := entity.SingleSignEntity(entitySigner, entityAccount, registry.RegisterEntitySignatureContext, &TestEntity)
	if err != nil {
		return fmt.Errorf("failed to sign entity: %w", err)
	}

	// Add a new entity to the registry. The test runner will check for its presence to verify
	// the migration ran successfully.
	if err = regState.SetEntity(abciCtx, &TestEntity, sigEntity); err != nil {
		return fmt.Errorf("failed to set entity: %w", err)
	}

	// Set this entity's staking properly.
	err = stakeState.SetAccount(abciCtx, entityAddress, &staking.Account{
		Escrow: staking.EscrowAccount{
			StakeAccumulator: staking.StakeAccumulator{
				Claims: map[staking.StakeClaim][]staking.StakeThreshold{
					registry.StakeClaimRegisterEntity: staking.GlobalStakeThresholds(
						staking.KindEntity,
					),
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set account: %w", err)
	}

	return nil
}
