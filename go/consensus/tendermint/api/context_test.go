package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

type testBlockContextKey struct{}

func (k testBlockContextKey) NewDefault() interface{} {
	return 42
}

// FooEvent is a test event.
type FooEvent struct {
	// Bar is the test event value.
	Bar []byte
}

// EventKind returns a string representation of this event's kind.
func (ev *FooEvent) EventKind() string {
	return "foo"
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
	child.EmitEvent(NewEventBuilder("test").TypedAttribute(&FooEvent{Bar: []byte("bar")}))
	require.Len(child.GetEvents(), 1, "child event should be stored")
	require.Len(ctx.GetEvents(), 0, "child event should not immediately propagate")
	events := child.GetEvents()

	child.Close()
	require.EqualValues(events, ctx.GetEvents(), "child events should propagate")

	// Emitting an event should not propagate to parent in simulation mode.
	ctx = appState.NewContext(ContextDeliverTx, now)
	defer ctx.Close()

	child = ctx.WithSimulation()
	child.EmitEvent(NewEventBuilder("test").TypedAttribute(&FooEvent{Bar: []byte("bar")}))
	child.Close()
	require.Empty(ctx.GetEvents(), "events should not propagate in simulation mode")

	child = ctx.WithMessageExecution()
	require.True(child.IsMessageExecution(), "child should have message execution enabled")
	require.False(ctx.IsMessageExecution(), "parent should not have message execution enabled")
	child.Close()
}

func TestTransactionContext(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := NewMockApplicationState(&MockApplicationStateConfig{})
	ctx := appState.NewContext(ContextDeliverTx, now)
	defer ctx.Close()

	child := ctx.NewTransaction()

	// Emitted events and state updates should not propagate to the parent unless committed.
	child.EmitEvent(NewEventBuilder("test").TypedAttribute(&FooEvent{Bar: []byte("bar")}))
	require.Len(child.GetEvents(), 1, "child event should be stored")
	require.Len(ctx.GetEvents(), 0, "child event should not immediately propagate")

	tree := child.State()
	err := tree.Insert(ctx, []byte("key"), []byte("value"))
	require.NoError(err, "Insert")

	child.Close()
	require.Len(ctx.GetEvents(), 0, "child event should not propagate unless committed")

	tree = ctx.State()
	value, err := tree.Get(ctx, []byte("key"))
	require.NoError(err, "Get")
	require.EqualValues([]byte(nil), value, "state updates should not propagate unless committed")

	// Emitted events and state updates should propagate if committed.
	ctx = appState.NewContext(ContextDeliverTx, now)
	defer ctx.Close()

	child = ctx.NewTransaction()

	child.EmitEvent(NewEventBuilder("test").TypedAttribute(&FooEvent{Bar: []byte("bar")}))
	require.Len(child.GetEvents(), 1, "child event should be stored")
	require.Len(ctx.GetEvents(), 0, "child event should not immediately propagate")
	events := child.GetEvents()

	tree = child.State()
	err = tree.Insert(ctx, []byte("key"), []byte("value"))
	require.NoError(err, "Insert")

	child.Commit()
	child.Close()
	require.EqualValues(events, ctx.GetEvents(), "child events should propagate after Commit")

	tree = ctx.State()
	value, err = tree.Get(ctx, []byte("key"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value"), value, "state updates should propagate after Commit")
}

func TestNestedTransactionContext(t *testing.T) {
	require := require.New(t)

	doChild2 := func(ctx *Context) {
		tree := ctx.State()

		err := tree.Insert(ctx, []byte("child2"), []byte("value2"))
		require.NoError(err, "Insert")

		value, err := tree.Get(ctx, []byte("top-level"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value"), value, "top-level state should be visible in child2 context")

		value, err = tree.Get(ctx, []byte("child1"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value1"), value, "child1 state should be visible in child2 context")

		value, err = tree.Get(ctx, []byte("child2"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value2"), value, "child2 state should be visible in child2 context")
	}

	doChild1 := func(ctx *Context) {
		tree := ctx.State()

		err := tree.Insert(ctx, []byte("child1"), []byte("value1"))
		require.NoError(err, "Insert")

		value, err := tree.Get(ctx, []byte("top-level"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value"), value, "top-level state should be visible in child1 context")

		// Start a new child transaction and rollback.
		child := ctx.NewTransaction()
		doChild2(child)
		child.Close()

		value, err = tree.Get(ctx, []byte("top-level"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value"), value, "top-level state should be visible in child1 context")

		value, err = tree.Get(ctx, []byte("child1"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value1"), value, "child1 state should be visible in child1 context")

		value, err = tree.Get(ctx, []byte("child2"))
		require.NoError(err, "Get")
		require.EqualValues([]byte(nil), value, "child2 state should be rolled back")

		// Start a new child transaction and commit.
		child = ctx.NewTransaction()
		doChild2(child)
		child.Commit()

		value, err = tree.Get(ctx, []byte("top-level"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value"), value, "top-level state should be visible in child1 context")

		value, err = tree.Get(ctx, []byte("child1"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value1"), value, "child1 state should be visible in child1 context")

		value, err = tree.Get(ctx, []byte("child2"))
		require.NoError(err, "Get")
		require.EqualValues([]byte("value2"), value, "child2 state should be committed")
	}

	now := time.Unix(1580461674, 0)
	appState := NewMockApplicationState(&MockApplicationStateConfig{})
	ctx := appState.NewContext(ContextDeliverTx, now)
	defer ctx.Close()

	// Insert some top-level state.
	tree := ctx.State()
	err := tree.Insert(ctx, []byte("top-level"), []byte("value"))
	require.NoError(err, "Insert")

	// Start a new child transaction and rollback.
	child := ctx.NewTransaction()
	doChild1(child)
	child.Close()

	value, err := tree.Get(ctx, []byte("top-level"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value"), value, "top-level state should be visible in top-level context")

	value, err = tree.Get(ctx, []byte("child1"))
	require.NoError(err, "Get")
	require.EqualValues([]byte(nil), value, "child1 state should be rolled back")

	value, err = tree.Get(ctx, []byte("child2"))
	require.NoError(err, "Get")
	require.EqualValues([]byte(nil), value, "child2 state should be rolled back")

	// Start a new child transaction and commit.
	child = ctx.NewTransaction()
	doChild1(child)
	child.Commit()

	value, err = tree.Get(ctx, []byte("top-level"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value"), value, "top-level state should be visible in top-level context")

	value, err = tree.Get(ctx, []byte("child1"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value1"), value, "child1 state should be committed")

	value, err = tree.Get(ctx, []byte("child2"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("value2"), value, "child2 state should be committed")
}
