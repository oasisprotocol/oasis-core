package api

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrors(t *testing.T) {
	require := require.New(t)

	err := fmt.Errorf("just an error")
	require.False(IsUnavailableStateError(err))

	err = UnavailableStateError(err)
	require.True(IsUnavailableStateError(err))

	err = fmt.Errorf("a wrapped error: %w", err)
	require.True(IsUnavailableStateError(err))

	err = fmt.Errorf("a doubly wrapped error: %w", err)
	require.True(IsUnavailableStateError(err))

	err = UnavailableStateError(nil)
	require.False(IsUnavailableStateError(err))

	var nilInterface *errorUnavailableState
	err = UnavailableStateError(nilInterface)
	require.False(IsUnavailableStateError(err))
}
