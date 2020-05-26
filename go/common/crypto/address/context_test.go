package address

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	require := require.New(t)

	// Make sure valid contexts can be registered.
	var ctx1V0, ctx1V1, ctx2V0 Context
	require.NotPanics(func() { ctx1V0 = NewContext("test: dummy context 1", 0) },
		"registering a new context should not panic")
	require.NotPanics(func() { ctx2V0 = NewContext("test: dummy context 2", 0) },
		"registering a new context should not panic")
	require.NotPanics(func() { ctx1V1 = NewContext("test: dummy context 1", 1) },
		"registering a context with the same identifier but different version should not panic")
	require.NotPanics(func() { NewContext("test: dummy context 2", 3) },
		"registering a context with the same identifier but different version should not panic")

	// Make sure registering invalid contexts panics.
	require.Panics(func() { NewContext("test: dummy context 1", 0) },
		"registering the same context twice should panic")
	require.Panics(func() { NewContext(strings.Repeat("a", 65), 0) },
		"registering a context with a too long identifier should panic")

	addressData := []byte("address data")

	// Make sure we cannot use an unregistered context.
	unregCtx := Context{"test: unregistered", 0}
	require.Panics(func() { NewAddress(unregCtx, addressData) },
		"creating an address with an unregistered context should panic")

	// Make sure creating addresses with registered contexts works.
	require.NotPanics(func() { NewAddress(ctx1V0, addressData) },
		"creating an address with a registered context should not panic")
	require.NotPanics(func() { NewAddress(ctx2V0, addressData) },
		"creating an address with a registered context should not panic")

	// Make sure addresses differ for different contexts.
	addr1 := NewAddress(ctx1V0, addressData)
	addr2 := NewAddress(ctx2V0, addressData)
	require.NotEqual(addr1, addr2, "addresses for different contexts should be different")

	// Make sure addresses differ for different context versions.
	addr3 := NewAddress(ctx1V0, addressData)
	addr4 := NewAddress(ctx1V1, addressData)
	require.NotEqual(addr3, addr4, "addresses for different context versions should be different")
}
