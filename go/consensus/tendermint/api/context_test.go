package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestContext(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := NewMockApplicationState(&MockApplicationStateConfig{})
	ctx := appState.NewContext(ContextBeginBlock, now)
	defer ctx.Close()

	// Add some state.
	tree := ctx.State()
	err := tree.Insert(ctx, []byte("key"), []byte("value"))
	require.NoError(err, "Insert")

	// Test checkpoints.
	cp := ctx.StartCheckpoint()
	// Should panic on nested checkpoints.
	require.Panics(func() { ctx.StartCheckpoint() })
	overlay := ctx.State()
	require.NotEqual(&tree, &overlay, "new State() should return the overlay")

	// Existing state should be there.
	value, err := overlay.Get(ctx, []byte("key"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value"), value)

	// Add some state to the overlay.
	err = overlay.Insert(ctx, []byte("blah"), []byte("value2"))
	require.NoError(err, "Insert")
	err = overlay.Remove(ctx, []byte("key"))
	require.NoError(err, "Remove")

	// Make sure updates didn't leak.
	value, err = tree.Get(ctx, []byte("key"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value"), value, "updates should not leak outside checkpoint")
	value, err = tree.Get(ctx, []byte("blah"))
	require.NoError(err, "Get")
	require.Nil(value, "updates should not leak outside checkpoint")

	// Commit checkpoint.
	cp.Commit()
	newTree := ctx.State()
	require.Equal(&tree, &newTree, "new State() should return the original tree")

	// Make sure updates were applied.
	value, err = tree.Get(ctx, []byte("key"))
	require.NoError(err, "Get")
	require.Nil(value, "updates should have been applied")
	value, err = tree.Get(ctx, []byte("blah"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value2"), value, "updates should have been applied")

	// Create another checkpoint to test rollback.
	cp = ctx.StartCheckpoint()
	overlay = ctx.State()
	err = overlay.Insert(ctx, []byte("blah"), []byte("rollback"))
	require.NoError(err, "Insert")
	cp.Close()

	// Make sure updates didn't leak.
	value, err = tree.Get(ctx, []byte("blah"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value2"), value, "updates should have been discarded")

	ctx.Close()
}

type testBlockContextKey struct{}

func (k testBlockContextKey) NewDefault() interface{} {
	return 42
}

func TestBlockContext(t *testing.T) {
	require := require.New(t)

	bc := NewBlockContext()

	value := bc.Get(testBlockContextKey{})
	require.EqualValues(42, value, "block context key should have default value")

	bc.Set(testBlockContextKey{}, 21)
	value = bc.Get(testBlockContextKey{})
	require.EqualValues(21, value, "block context key should have correct value")
}

func TestChildContext(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := NewMockApplicationState(&MockApplicationStateConfig{})
	ctx := appState.NewContext(ContextDeliverTx, now)
	defer ctx.Close()

	var pk1 signature.PublicKey
	addr1 := staking.NewAddress(pk1)

	ctx.SetTxSigner(pk1)
	require.Equal(addr1, ctx.CallerAddress(), "CallerAddress should correspond to TxSigner")

	pk2 := signature.NewPublicKey("1234567890000000000000000000000000000000000000000000000000000000")
	addr2 := staking.NewAddress(pk2)
	child := ctx.WithCallerAddress(addr2)
	require.EqualValues(addr2, child.CallerAddress(), "CallerAddress should correspond to pk2")
	require.EqualValues(ctx.Mode(), child.Mode(), "child.Mode should correspond to parent.Mode")
	require.EqualValues(ctx.Gas(), child.Gas(), "child.Gas should correspond to parent.Gas")
	require.EqualValues(ctx.Now(), child.Now(), "child.Now should correspond to parent.Now")
	require.EqualValues(ctx.State(), child.State(), "child.State should correspond to parent.State")
	require.EqualValues(ctx.AppState(), child.AppState(), "child.Mode should correspond to parent.Mode")
	require.EqualValues(ctx.InitialHeight(), child.InitialHeight(), "child.InitialHeight should correspond to parent.InitialHeight")
	require.EqualValues(ctx.BlockHeight(), child.BlockHeight(), "child.BlockHeight should correspond to parent.BlockHeight")
	require.EqualValues(ctx.BlockContext(), child.BlockContext(), "child.BlockContext should correspond to parent.BlockContext")

	// Emitting an event should not propagate to the parent immediately.
	child.EmitEvent(NewEventBuilder("test").Attribute([]byte("foo"), []byte("bar")))
	require.Len(child.GetEvents(), 1, "child event should be stored")
	require.Len(ctx.GetEvents(), 0, "child event should not immediately propagate")
	events := child.GetEvents()

	child.Close()
	require.EqualValues(events, ctx.GetEvents(), "child events should propagate")
}
