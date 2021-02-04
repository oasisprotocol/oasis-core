package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEscapeLabelCharacters(t *testing.T) {
	require := require.New(t)

	for _, tc := range []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"hello world", "hello_world"},
		{"one-two_three", "one_two_three"},
		{"a-b c.d.e.f--g", "a_b_c_d_e_f__g"},
	} {
		require.EqualValues(tc.expected, EscapeLabelCharacters(tc.input))
	}
}
