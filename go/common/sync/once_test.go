package sync

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFallibleOnce(t *testing.T) {
	t.Run("Successful execution", func(t *testing.T) {
		require := require.New(t)

		var once FallibleOnce
		counter := 0
		counterIncFn := func() error {
			counter++
			return nil
		}

		done := once.Done()
		require.False(done, "Function should not have completed successfully yet")

		err := once.Do(counterIncFn)
		require.NoError(err)
		require.Equal(1, counter, "Do should invoke the function")

		done = once.Done()
		require.True(done, "Function should have completed successfully")

		err = once.Do(counterIncFn)
		require.NoError(err)
		require.Equal(1, counter, "Do should not invoke the function again")

		done = once.Done()
		require.True(done, "Function should have completed successfully")
	})

	t.Run("Retry on error", func(t *testing.T) {
		require := require.New(t)

		var once FallibleOnce
		counter := 0
		counterIncErrFn := func() error {
			counter++
			if counter < 2 {
				return fmt.Errorf("error")
			}
			return nil
		}

		done := once.Done()
		require.False(done, "Function should not have completed successfully yet")

		err := once.Do(counterIncErrFn)
		require.Error(err)
		require.Equal(1, counter, "Do should invoke the function")

		done = once.Done()
		require.False(done, "Function should not have completed successfully yet")

		err = once.Do(counterIncErrFn)
		require.NoError(err)
		require.Equal(2, counter, "Do should invoke the function again on error")

		done = once.Done()
		require.True(done, "Function should have completed successfully")

		err = once.Do(counterIncErrFn)
		require.NoError(err)
		require.Equal(2, counter, "Do should not invoke the function again")

		done = once.Done()
		require.True(done, "Function should have completed successfully")
	})
}
