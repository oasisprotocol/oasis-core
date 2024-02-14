// Package sync provides sync primitives.
package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOne(t *testing.T) {
	noopFn := func(_ context.Context) {}
	blockFn := func(ctx context.Context) {
		<-ctx.Done()
	}

	t.Run("Non-blocking function", func(t *testing.T) {
		require := require.New(t)

		one := NewOne()

		// All functions should start and stop if there is big enough time gap
		// between starts.
		for i := 0; i < 3; i++ {
			require.True(one.TryStart(noopFn))
			time.Sleep(time.Millisecond)
		}

		// All stops should fail as no function is running.
		for i := 0; i < 3; i++ {
			require.False(one.TryStop())
		}

		// Starting functions again should not be a problem.
		for i := 0; i < 3; i++ {
			require.True(one.TryStart(noopFn))
			time.Sleep(time.Millisecond)
		}
	})

	t.Run("Blocking function", func(t *testing.T) {
		require := require.New(t)

		one := NewOne()

		// First function should start, others not.
		require.True(one.TryStart(blockFn))
		for i := 0; i < 3; i++ {
			require.False(one.TryStart(blockFn))
		}

		// As one function is running, the first stop should succeed,
		// others not.
		require.True(one.TryStop())
		for i := 0; i < 3; i++ {
			require.False(one.TryStop())
		}

		// Starting function again should not be a problem.
		require.True(one.TryStart(blockFn))
		require.True(one.TryStop())
	})
}
