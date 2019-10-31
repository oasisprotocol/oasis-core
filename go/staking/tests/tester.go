// Pacakge tests is a collection of staking token backend implementation tests.
package tests

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/identity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/staking/api"
)

const recvTimeout = 5 * time.Second

var (
	debugGenesisState = DebugGenesisState

	testTotalSupply = DebugStateTestTotalSupply
	qtyOne          = QtyFromInt(1)

	srcSigner = DebugStateSrcSigner
	SrcID     = DebugStateSrcID
	DestID    = DebugStateDestID
)

// StakingImplementationTests exercises the basic functionality of a
// staking token backend.
func StakingImplementationTests(
	t *testing.T,
	backend api.Backend,
	timeSource epochtime.SetableBackend,
	registry registry.Backend,
	roothash roothash.Backend,
	identity *identity.Identity,
	entity *entity.Entity,
	entitySigner signature.Signer,
	runtimeID signature.PublicKey,
) {
	for _, tc := range []struct {
		n  string
		fn func(*testing.T, api.Backend, epochtime.SetableBackend)
	}{
		{"InitialEnv", testInitialEnv},
		{"Transfer", testTransfer},
		{"TransferSelf", testSelfTransfer},
		{"Burn", testBurn},
		{"Escrow", testEscrow},
		{"EscrowSelf", testSelfEscrow},
	} {
		t.Run(tc.n, func(t *testing.T) { tc.fn(t, backend, timeSource) })
	}

	// Separate test as it requires some arguments that others don't.
	t.Run("SlashDoubleSigning", func(t *testing.T) {
		testSlashDoubleSigning(t, backend, timeSource, registry, roothash, identity, entity, entitySigner, runtimeID)
	})
}

func testInitialEnv(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background(), 0)
	require.NoError(err, "TotalSupply")
	require.Equal(&testTotalSupply, totalSupply, "TotalSupply - value")

	accounts, err := backend.Accounts(context.Background(), 0)
	require.NoError(err, "Accounts")
	require.Len(accounts, 1, "Accounts - nr entries")
	require.Equal(SrcID, accounts[0], "Accounts[0] == testID")

	acc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "src: AccountInfo")
	require.Equal(testTotalSupply, acc.General.Balance, "src: general balance")
	require.True(acc.Escrow.Active.Balance.IsZero(), "src: active escrow balance")
	require.True(acc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance")
	require.EqualValues(0, acc.General.Nonce, "src: nonce")

	commonPool, err := backend.CommonPool(context.Background(), 0)
	require.NoError(err, "CommonPool")
	require.True(commonPool.IsZero(), "CommonPool - initial value")

	for _, kind := range []api.ThresholdKind{
		api.KindValidator,
		api.KindCompute,
		api.KindStorage,
	} {
		qty, err := backend.Threshold(context.Background(), kind, 0)
		require.NoError(err, "Threshold")
		require.NotNil(qty, "Threshold != nil")
		require.Equal(debugGenesisState.Parameters.Thresholds[kind], *qty, "Threshold - value")
	}
}

func testTransfer(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	dstAcc, err := backend.AccountInfo(context.Background(), DestID, 0)
	require.NoError(err, "dest: AccountInfo")
	require.True(dstAcc.General.Balance.IsZero(), "dest: general balance - before")
	require.EqualValues(0, dstAcc.General.Nonce, "dest: nonce - before")

	srcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "src: AccountInfo - before")

	ch, sub := backend.WatchTransfers()
	defer sub.Close()

	xfer := &api.Transfer{
		Nonce:  srcAcc.General.Nonce,
		To:     DestID,
		Tokens: QtyFromInt(math.MaxUint8),
	}
	signed, err := api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer")

	err = backend.Transfer(context.Background(), signed)
	require.NoError(err, "Transfer")

	select {
	case ev := <-ch:
		require.Equal(SrcID, ev.From, "Event: from")
		require.Equal(DestID, ev.To, "Event: to")
		require.Equal(xfer.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive transfer event")
	}

	_ = srcAcc.General.Balance.Sub(&xfer.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(xfer.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	dstAcc, err = backend.AccountInfo(context.Background(), DestID, 0)
	require.NoError(err, "dest: AccountInfo - after")
	require.Equal(xfer.Tokens, dstAcc.General.Balance, "dest: general balance - after")
	require.EqualValues(0, dstAcc.General.Nonce, "dest: nonce - after")

	// Transfers that exceed available balance should fail.
	xfer.Nonce = newSrcAcc.General.Nonce
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Tokens = newSrcAcc.General.Balance

	signed, err = api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer - fail test")

	err = backend.Transfer(context.Background(), signed)
	require.Error(err, "Transfer - more than available balance")
}

func testSelfTransfer(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	srcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "src: AccountInfo - before")

	ch, sub := backend.WatchTransfers()
	defer sub.Close()

	xfer := &api.Transfer{
		Nonce:  srcAcc.General.Nonce,
		To:     SrcID,
		Tokens: QtyFromInt(math.MaxUint8),
	}
	signed, err := api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer")

	err = backend.Transfer(context.Background(), signed)
	require.NoError(err, "Transfer")

	select {
	case ev := <-ch:
		require.Equal(SrcID, ev.From, "Event: from")
		require.Equal(SrcID, ev.To, "Event: to")
		require.Equal(xfer.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive transfer event")
	}

	newSrcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.Equal(xfer.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	// Self transfers that are more than the balance should fail.
	xfer.Nonce = newSrcAcc.General.Nonce
	_ = newSrcAcc.General.Balance.Add(&qtyOne)
	xfer.Tokens = newSrcAcc.General.Balance

	signed, err = api.SignTransfer(srcSigner, xfer)
	require.NoError(err, "Sign xfer - fail test")

	err = backend.Transfer(context.Background(), signed)
	require.Error(err, "Transfer - more than available balance")
}

func testBurn(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	require := require.New(t)

	totalSupply, err := backend.TotalSupply(context.Background(), 0)
	require.NoError(err, "TotalSupply - before")

	srcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "src: AccountInfo")

	ch, sub := backend.WatchBurns()
	defer sub.Close()

	burn := &api.Burn{
		Nonce:  srcAcc.General.Nonce,
		Tokens: QtyFromInt(math.MaxUint32),
	}
	signed, err := api.SignBurn(srcSigner, burn)
	require.NoError(err, "Sign burn")

	err = backend.Burn(context.Background(), signed)
	require.NoError(err, "Burn")

	select {
	case ev := <-ch:
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(burn.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive burn event")
	}

	_ = totalSupply.Sub(&burn.Tokens)
	newTotalSupply, err := backend.TotalSupply(context.Background(), 0)
	require.NoError(err, "TotalSupply - after")
	require.Equal(totalSupply, newTotalSupply, "totalSupply is reduced by burn")

	_ = srcAcc.General.Balance.Sub(&burn.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "src: AccountInfo")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	require.EqualValues(burn.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")
}

func testEscrow(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	testEscrowEx(t, backend, timeSource, SrcID, srcSigner, DestID)
}

func testSelfEscrow(t *testing.T, backend api.Backend, timeSource epochtime.SetableBackend) {
	testEscrowEx(t, backend, timeSource, SrcID, srcSigner, SrcID)
}

func testEscrowEx(
	t *testing.T,
	backend api.Backend,
	timeSource epochtime.SetableBackend,
	srcID signature.PublicKey,
	srcSigner signature.Signer,
	dstID signature.PublicKey,
) {
	require := require.New(t)

	srcAcc, err := backend.AccountInfo(context.Background(), srcID, 0)
	require.NoError(err, "src: AccountInfo - before")
	require.False(srcAcc.General.Balance.IsZero(), "src: general balance != 0")
	require.True(srcAcc.Escrow.Active.Balance.IsZero(), "src: active escrow balance == 0")
	require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0")

	dstAcc, err := backend.AccountInfo(context.Background(), dstID, 0)
	require.NoError(err, "dst: AccountInfo - before")
	require.True(dstAcc.Escrow.Active.Balance.IsZero(), "dst: active escrow balance == 0")
	require.True(dstAcc.Escrow.Active.TotalShares.IsZero(), "dst: active escrow total shares == 0")
	require.True(dstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0")
	require.True(dstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0")

	ch, sub := backend.WatchEscrows()
	defer sub.Close()

	var totalEscrowed api.Quantity

	// Escrow.
	escrow := &api.Escrow{
		Nonce:   srcAcc.General.Nonce,
		Account: dstID,
		Tokens:  QtyFromInt(math.MaxUint32),
	}
	signed, err := api.SignEscrow(srcSigner, escrow)
	require.NoError(err, "Sign escrow")

	err = backend.AddEscrow(context.Background(), signed)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Tokens))

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.EscrowEvent)
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(dstID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	_ = srcAcc.General.Balance.Sub(&escrow.Tokens)
	newSrcAcc, err := backend.AccountInfo(context.Background(), srcID, 0)
	require.NoError(err, "src: AccountInfo - after")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after")
	if !srcID.Equal(dstID) {
		require.True(newSrcAcc.Escrow.Active.Balance.IsZero(), "src: active escrow balance == 0 - after")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after")
	}
	require.Equal(escrow.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after")

	_ = dstAcc.Escrow.Active.Balance.Add(&escrow.Tokens)
	newDstAcc, err := backend.AccountInfo(context.Background(), dstID, 0)
	require.NoError(err, "dst: AccountInfo - after")
	if !srcID.Equal(dstID) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after")
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Escrow some more.
	escrow = &api.Escrow{
		Nonce:   srcAcc.General.Nonce,
		Account: dstID,
		Tokens:  QtyFromInt(math.MaxUint32),
	}
	signed, err = api.SignEscrow(srcSigner, escrow)
	require.NoError(err, "Sign escrow")

	err = backend.AddEscrow(context.Background(), signed)
	require.NoError(err, "AddEscrow")
	require.NoError(totalEscrowed.Add(&escrow.Tokens))

	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.EscrowEvent)
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(dstID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	_ = srcAcc.General.Balance.Sub(&escrow.Tokens)
	newSrcAcc, err = backend.AccountInfo(context.Background(), srcID, 0)
	require.NoError(err, "src: AccountInfo - after 2nd")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after 2nd")
	if !srcID.Equal(dstID) {
		require.True(newSrcAcc.Escrow.Active.Balance.IsZero(), "src: active escrow balance == 0 - after 2nd")
		require.True(newSrcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after 2nd")
	}
	require.Equal(escrow.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after 2nd")

	_ = dstAcc.Escrow.Active.Balance.Add(&escrow.Tokens)
	newDstAcc, err = backend.AccountInfo(context.Background(), dstID, 0)
	require.NoError(err, "dst: AccountInfo - after 2nd")
	if !srcID.Equal(dstID) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after 2nd")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after 2nd")
	}
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.Balance, "dst: active escrow balance - after 2nd")
	require.Equal(dstAcc.Escrow.Active.Balance, newDstAcc.Escrow.Active.TotalShares, "dst: active escrow total shares - after 2nd")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after 2nd")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after 2nd")

	srcAcc = newSrcAcc
	dstAcc = newDstAcc
	newSrcAcc = nil
	newDstAcc = nil

	// Reclaim escrow (subject to debonding).
	debs, err := backend.DebondingDelegations(context.Background(), srcID, 0)
	require.NoError(err, "DebondingDelegations - before")
	require.Len(debs, 0, "no debonding delegations before reclaiming escrow")

	reclaim := &api.ReclaimEscrow{
		Nonce:   srcAcc.General.Nonce,
		Account: dstID,
		Shares:  dstAcc.Escrow.Active.TotalShares,
	}
	signedReclaim, err := api.SignReclaimEscrow(srcSigner, reclaim)
	require.NoError(err, "Sign ReclaimEscrow")

	err = backend.ReclaimEscrow(context.Background(), signedReclaim)
	require.NoError(err, "ReclaimEscrow")

	// Query debonding delegations.
	debs, err = backend.DebondingDelegations(context.Background(), srcID, 0)
	require.NoError(err, "DebondingDelegations - after (in debonding)")
	require.Len(debs, 1, "one debonding delegation after reclaiming escrow")
	require.Len(debs[dstID.ToMapKey()], 1, "one debonding delegation after reclaiming escrow")

	// Advance epoch to trigger debonding.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for debonding period to pass.
	select {
	case rawEv := <-ch:
		ev := rawEv.(*api.ReclaimEscrowEvent)
		require.Equal(srcID, ev.Owner, "Event: owner")
		require.Equal(dstID, ev.Escrow, "Event: escrow")
		require.Equal(&totalEscrowed, &ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive reclaim escrow event")
	}

	_ = srcAcc.General.Balance.Add(&totalEscrowed)
	newSrcAcc, err = backend.AccountInfo(context.Background(), srcID, 0)
	require.NoError(err, "src: AccountInfo - after debond")
	require.Equal(srcAcc.General.Balance, newSrcAcc.General.Balance, "src: general balance - after debond")
	if !srcID.Equal(dstID) {
		require.True(srcAcc.Escrow.Active.Balance.IsZero(), "src: active escrow balance == 0 - after debond")
		require.True(srcAcc.Escrow.Debonding.Balance.IsZero(), "src: debonding escrow balance == 0 - after debond")
	}
	require.Equal(reclaim.Nonce+1, newSrcAcc.General.Nonce, "src: nonce - after debond")

	newDstAcc, err = backend.AccountInfo(context.Background(), dstID, 0)
	require.NoError(err, "dst: AccountInfo - after debond")
	if !srcID.Equal(dstID) {
		require.Equal(dstAcc.General.Balance, newDstAcc.General.Balance, "dst: general balance - after debond")
		require.Equal(dstAcc.General.Nonce, newDstAcc.General.Nonce, "dst: nonce - after debond")
	}
	require.True(newDstAcc.Escrow.Active.Balance.IsZero(), "dst: active escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Active.TotalShares.IsZero(), "dst: active escrow total shares == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.Balance.IsZero(), "dst: debonding escrow balance == 0 - after debond")
	require.True(newDstAcc.Escrow.Debonding.TotalShares.IsZero(), "dst: debonding escrow total shares == 0 - after debond")

	debs, err = backend.DebondingDelegations(context.Background(), srcID, 0)
	require.NoError(err, "DebondingDelegations - after (debonding completed)")
	require.Len(debs, 0, "no debonding delegations after debonding has completed")

	// Reclaim escrow (without enough shares).
	reclaim = &api.ReclaimEscrow{
		Nonce:   newSrcAcc.General.Nonce,
		Account: dstID,
		Shares:  reclaim.Shares,
	}
	signedReclaim, err = api.SignReclaimEscrow(srcSigner, reclaim)
	require.NoError(err, "Sign ReclaimEscrow")

	err = backend.ReclaimEscrow(context.Background(), signedReclaim)
	require.Error(err, "ReclaimEscrow")

	debs, err = backend.DebondingDelegations(context.Background(), srcID, 0)
	require.NoError(err, "DebondingDelegations")
	require.Len(debs, 0, "no debonding delegations after failed reclaim")
}

func testSlashDoubleSigning(
	t *testing.T,
	backend api.Backend,
	timeSource epochtime.SetableBackend,
	reg registry.Backend,
	roothash roothash.Backend,
	ident *identity.Identity,
	ent *entity.Entity,
	entSigner signature.Signer,
	runtimeID signature.PublicKey,
) {
	require := require.New(t)

	// Delegate some stake to the validator so we can check if slashing works.
	srcAcc, err := backend.AccountInfo(context.Background(), SrcID, 0)
	require.NoError(err, "AccountInfo")

	escrowCh, escrowSub := backend.WatchEscrows()
	defer escrowSub.Close()

	escrow := &api.Escrow{
		Nonce:   srcAcc.General.Nonce,
		Account: ent.ID,
		Tokens:  QtyFromInt(math.MaxUint32),
	}
	signed, err := api.SignEscrow(srcSigner, escrow)
	require.NoError(err, "Sign escrow")

	err = backend.AddEscrow(context.Background(), signed)
	require.NoError(err, "AddEscrow")

	select {
	case rawEv := <-escrowCh:
		ev := rawEv.(*api.EscrowEvent)
		require.Equal(SrcID, ev.Owner, "Event: owner")
		require.Equal(ent.ID, ev.Escrow, "Event: escrow")
		require.Equal(escrow.Tokens, ev.Tokens, "Event: tokens")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive escrow event")
	}

	// Subscribe to roothash blocks.
	blocksCh, blocksSub, err := roothash.WatchBlocks(runtimeID)
	require.NoError(err, "WatchBlocks")
	defer blocksSub.Close()

	// Subscribe to slash events.
	slashCh, slashSub := backend.WatchEscrows()
	defer slashSub.Close()

	// Broadcast evidence. This is Tendermint-specific, if we ever have more than one
	// consensus backend, we need to change this part.
	err = backend.SubmitEvidence(context.Background(), tendermintMakeDoubleSignEvidence(t, ident))
	require.NoError(err, "SubmitEvidence")

	// Wait for the node to get slashed.
WaitLoop:
	for {
		select {
		case ev := <-slashCh:
			if e, ok := ev.(*api.TakeEscrowEvent); ok {
				require.Equal(ent.ID, e.Owner, "TakeEscrowEvent - owner must be entity")
				// All tokens must be slashed as defined in debugGenesisState.
				require.Equal(escrow.Tokens, e.Tokens, "TakeEscrowEvent - all tokens slashed")
				break WaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive slash event")
		}
	}

	// Make sure the node is frozen.
	nodeStatus, err := reg.GetNodeStatus(context.Background(), ident.NodeSigner.Public(), 0)
	require.NoError(err, "GetNodeStatus")
	require.False(nodeStatus.ExpirationProcessed, "ExpirationProcessed should be false")
	require.True(nodeStatus.IsFrozen(), "IsFrozen() should return true")

	// Make sure node cannot be unfrozen.
	unfreeze := registry.UnfreezeNode{
		NodeID:    ident.NodeSigner.Public(),
		Timestamp: uint64(time.Now().Unix()),
	}
	signedUnfreeze, err := registry.SignUnfreezeNode(entSigner, registry.RegisterUnfreezeNodeSignatureContext, &unfreeze)
	require.NoError(err, "SignUnfreezeNode")
	err = reg.UnfreezeNode(context.Background(), signedUnfreeze)
	require.Error(err, "UnfreezeNode")

	// Wait for roothash block as re-scheduling must have taken place due to slashing.
	select {
	case blk := <-blocksCh:
		require.Equal(block.EpochTransition, blk.Block.Header.HeaderType)
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive roothash block")
	}

	// Advance epoch to make the freeze period expire.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Unfreeze node (now it should work).
	err = reg.UnfreezeNode(context.Background(), signedUnfreeze)
	require.NoError(err, "UnfreezeNode")

	// Advance epoch to restore committees.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Make sure the node is no longer frozen.
	nodeStatus, err = reg.GetNodeStatus(context.Background(), ident.NodeSigner.Public(), 0)
	require.NoError(err, "GetNodeStatus")
	require.False(nodeStatus.ExpirationProcessed, "ExpirationProcessed should be false")
	require.False(nodeStatus.IsFrozen(), "IsFrozen() should return false")
}
