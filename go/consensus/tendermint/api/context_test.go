package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
