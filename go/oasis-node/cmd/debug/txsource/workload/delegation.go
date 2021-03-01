package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// NameDelegation is the name of the delegation workload.
const NameDelegation = "delegation"

// Delegation is the delegation workload.
var Delegation = &delegation{
	BaseWorkload: NewBaseWorkload(NameDelegation),
}

const (
	delegationNumAccounts = 10
	delegateAmount        = 100
)

type delegation struct {
	BaseWorkload

	accounts []struct {
		signer        signature.Signer
		reckonedNonce uint64
		debondEndTime uint64
		address       staking.Address
		delegatedTo   staking.Address
	}
}

func (d *delegation) doEscrowTx(ctx context.Context, rng *rand.Rand) error {
	d.Logger.Debug("escrow tx flow")

	// Get current epoch.
	epoch, err := d.Consensus().Beacon().GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("GetEpoch: %w", err)
	}

	// Select an account that has no active delegations nor debonding funds.
	perm := rng.Perm(delegationNumAccounts)
	fromPermIdx := -1
	var empty staking.Address
	for i := range d.accounts {
		if d.accounts[perm[i]].delegatedTo == empty && d.accounts[perm[i]].debondEndTime < uint64(epoch) {
			fromPermIdx = i
			break
		}
	}
	if fromPermIdx == -1 {
		d.Logger.Debug("all accounts already delegating or debonding, skipping delegation")
		return nil
	}

	// Select an account to delegate to.
	toPermIdx := rng.Intn(delegationNumAccounts)

	// Remember index.
	selectedIdx := perm[fromPermIdx]

	// Update local state.
	d.accounts[selectedIdx].delegatedTo = d.accounts[perm[toPermIdx]].address

	// Create escrow tx.
	escrow := &staking.Escrow{
		Account: d.accounts[selectedIdx].delegatedTo,
	}
	if err = escrow.Amount.FromInt64(delegateAmount); err != nil {
		return fmt.Errorf("escrow amount error: %w", err)
	}

	tx := staking.NewAddEscrowTx(d.accounts[selectedIdx].reckonedNonce, nil, escrow)
	d.accounts[selectedIdx].reckonedNonce++
	// We only do one escrow per account at a time, so `delegateAmount`
	// funds (that are Escrowed) should already be in the balance.
	if err := d.FundSignAndSubmitTx(ctx, d.accounts[selectedIdx].signer, tx); err != nil {
		d.Logger.Error("failed to sign and submit escrow transaction",
			"tx", tx,
			"signer", d.accounts[selectedIdx].signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	return nil
}

func (d *delegation) doReclaimEscrowTx(ctx context.Context, rng *rand.Rand, stakingClient staking.Backend) error {
	d.Logger.Debug("reclaim escrow tx")

	// Select an account that has active delegation.
	perm := rng.Perm(delegationNumAccounts)
	fromPermIdx := -1
	var empty staking.Address
	for i := range d.accounts {
		if d.accounts[perm[i]].delegatedTo != empty {
			fromPermIdx = i
			break
		}
	}
	if fromPermIdx == -1 {
		d.Logger.Debug("no accounts delegating, skipping reclaim")
		return nil
	}
	selectedIdx := perm[fromPermIdx]

	// Query amount of delegated shares for the account.
	delegations, err := stakingClient.DelegationsFor(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  d.accounts[selectedIdx].address,
	})
	if err != nil {
		return fmt.Errorf("stakingClient.Delegations %s: %w", d.accounts[selectedIdx].signer.Public(), err)
	}
	delegation := delegations[d.accounts[selectedIdx].delegatedTo]
	if delegation == nil {
		d.Logger.Error("missing expected delegation",
			"delegator", d.accounts[selectedIdx].signer.Public(),
			"account", d.accounts[selectedIdx].delegatedTo,
			"delegations", delegations,
		)
		return fmt.Errorf("missing expected delegation by account: %s in account: %s",
			d.accounts[selectedIdx].signer.Public(), d.accounts[selectedIdx].delegatedTo)
	}

	// Create ReclaimEscrow tx.
	reclaim := &staking.ReclaimEscrow{
		Account: d.accounts[selectedIdx].delegatedTo,
		Shares:  delegation.Shares,
	}
	tx := staking.NewReclaimEscrowTx(d.accounts[selectedIdx].reckonedNonce, nil, reclaim)
	d.accounts[selectedIdx].reckonedNonce++
	if err = d.FundSignAndSubmitTx(ctx, d.accounts[selectedIdx].signer, tx); err != nil {
		d.Logger.Error("failed to sign and submit reclaim escrow transaction",
			"tx", tx,
			"signer", d.accounts[selectedIdx].signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	// Query debonding end epoch for the account.
	var debondingDelegations map[staking.Address][]*staking.DebondingDelegation
	debondingDelegations, err = stakingClient.DebondingDelegationsFor(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  d.accounts[selectedIdx].address,
	})
	if err != nil {
		return fmt.Errorf("stakingClient.Delegations %s: %w", d.accounts[selectedIdx].signer.Public(), err)
	}
	debondingDelegation := debondingDelegations[d.accounts[selectedIdx].delegatedTo]
	if len(debondingDelegation) == 0 {
		d.Logger.Error("missing expected debonding delegation",
			"delegator", d.accounts[selectedIdx].signer.Public(),
			"account", d.accounts[selectedIdx].delegatedTo,
			"debonding_delegations", debondingDelegation,
		)
		return fmt.Errorf("missing expected debonding delegation by account: %s in account: %s",
			d.accounts[selectedIdx].signer.Public(), d.accounts[selectedIdx].delegatedTo)
	}

	// Update local state.
	d.accounts[selectedIdx].delegatedTo = empty
	d.accounts[selectedIdx].debondEndTime = uint64(debondingDelegation[0].DebondEndTime)

	return nil
}

// Implements Workload.
func (d *delegation) NeedsFunds() bool {
	return true
}

// Implements Workload.
func (d *delegation) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	fundingAccount signature.Signer,
	validatorEntities []signature.Signer,
) error {
	// Initialize base workload.
	d.BaseWorkload.Init(cnsc, sm, fundingAccount)

	ctx := context.Background()

	fac := memorySigner.NewFactory()
	d.accounts = make([]struct {
		signer        signature.Signer
		reckonedNonce uint64
		debondEndTime uint64
		address       staking.Address
		delegatedTo   staking.Address
	}, delegationNumAccounts)

	for i := range d.accounts {
		signer, err := fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
		d.accounts[i].signer = signer
		d.accounts[i].address = staking.NewAddress(signer.Public())

		// Fund the account with delegation amount.
		// Funds for fees will be transferred before making transactions.
		if err = d.TransferFunds(ctx, fundingAccount, d.accounts[i].address, delegateAmount); err != nil {
			return fmt.Errorf("account funding failure: %w", err)
		}
	}

	stakingClient := staking.NewStakingClient(conn)

	for {
		switch rng.Intn(2) {
		case 0:
			if err := d.doEscrowTx(ctx, rng); err != nil {
				return err
			}
		case 1:
			if err := d.doReclaimEscrowTx(ctx, rng, stakingClient); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unimplemented")
		}

		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			d.Logger.Debug("time's up")
			return nil
		}
	}
}
