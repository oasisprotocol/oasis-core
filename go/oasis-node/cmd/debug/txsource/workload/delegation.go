package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// NameDelegation is the name of the delegation workload.
	NameDelegation = "delegation"

	delegationNumAccounts = 10
	delegateAmount        = 100
)

type delegation struct {
	logger *logging.Logger

	accounts []struct {
		signer        signature.Signer
		reckonedNonce uint64
		debondEndTime uint64
		address       staking.Address
		delegatedTo   staking.Address
	}
	fundingAccount signature.Signer
}

func (d *delegation) doEscrowTx(ctx context.Context, rng *rand.Rand, cnsc consensus.ClientBackend) error {
	d.logger.Debug("escrow tx flow")

	// Get current epoch.
	epoch, err := cnsc.GetEpoch(ctx, consensus.HeightLatest)
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
		d.logger.Debug("all accounts already delegating or debonding, skipping delegation")
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
	if err = escrow.Tokens.FromInt64(delegateAmount); err != nil {
		return fmt.Errorf("escrow amount error: %w", err)
	}

	tx := staking.NewAddEscrowTx(d.accounts[selectedIdx].reckonedNonce, &transaction.Fee{}, escrow)
	d.accounts[selectedIdx].reckonedNonce++
	// We only do one escrow per account at a time, so `delegateAmount`
	// funds (that are Escrowed) should already be in the balance.
	if err := fundSignAndSubmitTx(ctx, d.logger, cnsc, d.accounts[selectedIdx].signer, tx, d.fundingAccount); err != nil {
		d.logger.Error("failed to sign and submit escrow transaction",
			"tx", tx,
			"signer", d.accounts[selectedIdx].signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	return nil
}

func (d *delegation) doReclaimEscrowTx(ctx context.Context, rng *rand.Rand, cnsc consensus.ClientBackend, stakingClient staking.Backend) error {
	d.logger.Debug("reclaim escrow tx")

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
		d.logger.Debug("no accounts delegating, skipping reclaim")
		return nil
	}
	selectedIdx := perm[fromPermIdx]

	// Query amount of delegated shares for the account.
	delegations, err := stakingClient.Delegations(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  d.accounts[selectedIdx].address,
	})
	if err != nil {
		return fmt.Errorf("stakingClient.Delegations %s: %w", d.accounts[selectedIdx].signer.Public(), err)
	}
	delegation := delegations[d.accounts[selectedIdx].delegatedTo]
	if delegation == nil {
		d.logger.Error("missing expected delegation",
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
	tx := staking.NewReclaimEscrowTx(d.accounts[selectedIdx].reckonedNonce, &transaction.Fee{}, reclaim)
	d.accounts[selectedIdx].reckonedNonce++
	if err = fundSignAndSubmitTx(ctx, d.logger, cnsc, d.accounts[selectedIdx].signer, tx, d.fundingAccount); err != nil {
		d.logger.Error("failed to sign and submit reclaim escrow transaction",
			"tx", tx,
			"signer", d.accounts[selectedIdx].signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	// Query debonding end epoch for the account.
	var debondingDelegations map[staking.Address][]*staking.DebondingDelegation
	debondingDelegations, err = stakingClient.DebondingDelegations(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  d.accounts[selectedIdx].address,
	})
	if err != nil {
		return fmt.Errorf("stakingClient.Delegations %s: %w", d.accounts[selectedIdx].signer.Public(), err)
	}
	debondingDelegation := debondingDelegations[d.accounts[selectedIdx].delegatedTo]
	if len(debondingDelegation) == 0 {
		d.logger.Error("missing expected debonding delegation",
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

func (d *delegation) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	fundingAccount signature.Signer,
) error {
	ctx := context.Background()

	d.logger = logging.GetLogger("cmd/txsource/workload/delegation")
	d.fundingAccount = fundingAccount

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
		if err = transferFunds(ctx, d.logger, cnsc, fundingAccount, d.accounts[i].address, delegateAmount); err != nil {
			return fmt.Errorf("account funding failure: %w", err)
		}
	}

	stakingClient := staking.NewStakingClient(conn)

	for {
		switch rng.Intn(2) {
		case 0:
			if err := d.doEscrowTx(ctx, rng, cnsc); err != nil {
				return err
			}
		case 1:
			if err := d.doReclaimEscrowTx(ctx, rng, cnsc, stakingClient); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unimplemented")
		}

		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			d.logger.Debug("time's up")
			return nil
		}
	}
}
