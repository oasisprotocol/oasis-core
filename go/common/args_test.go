package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrimArgs(t *testing.T) {
	require := require.New(t)

	// If there's no separator the function should return the binary name.
	args := TrimArgs([]string{"foo", "bar", "moo"})
	require.Equal([]string{"foo"}, args, "TrimArgs should return the binary name when there's no separator")

	// Should correctly trim.
	args = TrimArgs([]string{"foo", "bar", "--", "more", "args"})
	require.EqualValues([]string{"foo", "more", "args"}, args, "TrimArgs should correctly trim arguments")

	// Separator as the last token.
	args = TrimArgs([]string{"foo", "bar", "--"})
	require.EqualValues([]string{"foo"}, args, "TrimArgs should return the binary name with no extra args")

	// Should panic on empty slice.
	require.Panics(func() { TrimArgs(nil) })
	require.Panics(func() { TrimArgs([]string{}) })
}
