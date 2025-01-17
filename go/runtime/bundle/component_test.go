package bundle

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
)

func TestComponentValidation(t *testing.T) {
	require := require.New(t)

	// Test component names.
	var comp Component
	err := comp.Validate()
	require.ErrorContains(err, "unknown component kind")
	comp.Kind = component.ROFL

	for _, tc := range []struct {
		name string
		err  string
	}{
		{"", "ROFL component name must be at least 3 characters long"},
		{strings.Repeat("a", 129), "ROFL component name must be at most 128 characters long"},
		{"my invalid component name", "ROFL component name is invalid"},
		{"my.invalid.component.name", "ROFL component name is invalid"},
		{"my:invalid:component:name", "ROFL component name is invalid"},
		{"my-valid-component-name", ""},
	} {
		comp.Name = tc.name
		err = comp.Validate()
		if tc.err == "" {
			require.NoError(err)
		} else {
			require.ErrorContains(err, tc.err)
		}
	}
}
