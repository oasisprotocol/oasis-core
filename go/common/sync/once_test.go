package sync

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFallibleOnce(t *testing.T) {
	require := require.New(t)

	var once FallibleOnce
	counter := 0
	counterIncFn := func() error {
		counter++
		return nil
	}

	err := once.Do(counterIncFn)
	require.NoError(err)
	require.Equal(1, counter, "Do should invoke the function")

	err = once.Do(counterIncFn)
	require.NoError(err)
	require.Equal(1, counter, "Do should not invoke the function again")

	var onceErr FallibleOnce
	counter = 0
	counterIncErrFn := func() error {
		counter++
		if counter < 2 {
			return fmt.Errorf("error")
		}
		return nil
	}

	err = onceErr.Do(counterIncErrFn)
	require.Error(err)
	require.Equal(1, counter, "Do should invoke the function")

	err = onceErr.Do(counterIncErrFn)
	require.NoError(err)
	require.Equal(2, counter, "Do should invoke the function again on error")

	err = onceErr.Do(counterIncErrFn)
	require.NoError(err)
	require.Equal(2, counter, "Do should not invoke the function again")
}
