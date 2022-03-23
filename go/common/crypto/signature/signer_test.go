package signature

import (
	"errors"
	"strings"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	require := require.New(t)

	// Make sure a context can be registered.
	var ctx, ctx2, ctx3 Context
	require.NotPanics(func() { ctx = NewContext("test: dummy context 1") })
	require.NotPanics(func() { ctx2 = NewContext("test: dummy context 2") })
	require.NotPanics(func() { ctx3 = NewContext("test: dummy context 3", WithDynamicSuffix(" for test suffix ", 1)) })

	// Make sure we panic if the same context is registered twice.
	require.Panics(func() { NewContext("test: dummy context 1") })
	// Even with different options.
	require.Panics(func() { NewContext("test: dummy context 1", WithChainSeparation()) })
	require.Panics(func() { NewContext("test: dummy context 3") })

	// Make sure we panic if context is too long.
	require.Panics(func() { NewContext(strings.Repeat("a", 500)) })

	// Make sure we panic if context includes the chain context separator.
	require.Panics(func() { NewContext("test: dummy context 1 for chain blah") })

	// Make sure we panic if suffix is too long.
	require.Panics(func() { NewContext("test: dummy", WithDynamicSuffix(" for test suffix ", 500)) })

	// Make sure we cannot use an unregistered context.
	unregCtx := Context("test: unregistered")
	_, err := PrepareSignerMessage(unregCtx, []byte("message"))
	require.Error(err, "PrepareSignerMessage should fail with unregistered context")

	_, err = unregCtx.WithSuffix("1")
	require.Error(err, "WithSuffix should fail on unregistered context")

	// Should work with registered context.
	msg1, err := PrepareSignerMessage(ctx, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	msg2, err := PrepareSignerMessage(ctx2, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	require.NotEqual(msg1, msg2, "messages for different contexts should be different")

	// Context without dynamic suffix should fail.
	_, err = ctx2.WithSuffix("1")
	require.Equal(err, errNoSuffixConfigured, "context suffix not configured")
	// Suffix to big should fail.
	_, err = ctx3.WithSuffix(strings.Repeat("a", 500))
	require.True(errors.Is(err, errMalformedContext), "context dynamic suffix too long")
	// Dynamic suffix without context suffix should fail
	_, err = PrepareSignerMessage(ctx3, []byte("message"))
	require.Equal(errNoDynamicSuffix, err, "PrepareSignerMessage should fail for dynamic context without suffix")

	// Should work with different dynamic suffixes.
	ctx3Pre1, err := ctx3.WithSuffix("1")
	require.NoError(err, "Ctx3 WithSuffix 1")
	ctx3Pre2, err := ctx3.WithSuffix("2")
	require.NoError(err, "Ctx3 WithSuffix 2")
	msg1, err = PrepareSignerMessage(ctx3Pre1, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	msg2, err = PrepareSignerMessage(ctx3Pre2, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	require.NotEqual(msg1, msg2, "messages for different dynamic suffixes should be different")

	// Setting suffix multiple times should fail.
	_, err = ctx3Pre1.WithSuffix("1")
	require.Equal(err, errNoSuffixConfigured, "setting dynamic suffix multiple times should fail")

	// Make sure a context with chain separation and dynamic suffix can be registered.
	var chainCtx Context
	require.NotPanics(func() {
		chainCtx = NewContext("test: dummy context 4", WithChainSeparation(), WithDynamicSuffix(" for test ", 1))
	})
	chainCtx1, err := chainCtx.WithSuffix("1")
	require.NoError(err, "chain context with suffix")

	// Should fail with context that requires chain separation as no
	// chain context has been set.
	_, err = PrepareSignerMessage(chainCtx1, []byte("message"))
	require.Error(err, "PrepareSignerMessage should fail without chain context")

	// Make sure we can set a chain context.
	require.NotPanics(func() { SetChainContext("test: oasis-core tests 1") })
	// Make sure we can set the same chain context again.
	require.NotPanics(func() { SetChainContext("test: oasis-core tests 1") })
	// Make sure we can't modify a set chain context.
	require.Panics(func() { SetChainContext("test: context change") })

	_, err = PrepareSignerMessage(chainCtx, []byte("message"))
	require.Equal(err, errNoDynamicSuffix, "PrepareSignerMessage should fail with chain context without suffix")

	msg1, err = PrepareSignerMessage(chainCtx1, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work with chain context")

	// Manually change the chain context to test that this generates different
	// messages with different contexts (this is otherwise not allowed).
	UnsafeResetChainContext()
	SetChainContext("test: oasis-core tests")

	msg2, err = PrepareSignerMessage(chainCtx1, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work with chain context")
	require.NotEqual(msg1, msg2, "messages for different chain contexts should be different")

	// Manually delete a registered context so that we can re-register with
	// different options and check that the messages are different.
	registeredContexts.Delete(chainCtx)
	registeredContexts.Delete(chainCtx1)

	chainCtx = NewContext("test: dummy context 4", WithDynamicSuffix(" for test ", 1))
	chainCtx1, err = chainCtx.WithSuffix("1")
	require.NoError(err, "chain context with suffix")

	msg3, err := PrepareSignerMessage(chainCtx1, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	require.NotEqual(msg2, msg3, "messages for different contexts should be different")

	chainCtx2, err := chainCtx.WithSuffix("2")
	require.NoError(err, "chain context with suffix")
	msg4, err := PrepareSignerMessage(chainCtx2, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work")
	require.NotEqual(msg3, msg4, "messages for different contexts should be different")

	ctx5 := NewContext("test: dummy context 5", WithChainSeparation())
	msg5, err := PrepareSignerMessage(ctx5, []byte("message"))
	require.NoError(err, "PrepareSignerMessage before UnsafeResetChainContext")

	// The remote signer requires bypassing the context registration checks.
	UnsafeAllowUnregisteredContexts()
	defer func() {
		allowUnregisteredContexts = false
	}()
	require.True(IsUnsafeUnregisteredContextsAllowed(), "context registration must be bypassed")

	_, err = PrepareSignerMessage(unregCtx, []byte("message"))
	require.NoError(err, "PrepareSignerMessage should work with unregisered context (bypassed)")

	overlongUnregCtx := Context("test: l" + strings.Repeat("o", ed25519.ContextMaxSize) + "ng")
	_, err = PrepareSignerMessage(overlongUnregCtx, []byte("message"))
	require.Error(err, "PrepareSignerMessage should fail with overlong unregistered context")

	msg5UAUC, err := PrepareSignerMessage(ctx5, []byte("message"))
	require.NoError(err, "PrepareSignerMessage after UnsafeAllowUnregisteredContexts")
	require.Equal(msg5, msg5UAUC, "message for same chain context should be same")
}

func TestSignerRoles(t *testing.T) {
	require := require.New(t)

	// Make sure marshaling and unmarshaling works.
	var unmarshaled SignerRole
	for _, role := range SignerRoles {
		text, err := role.MarshalText()
		require.NoError(err, "marshal SignerRole")
		err = unmarshaled.UnmarshalText(text)
		require.NoError(err, "unmarshal previously marshaled SignerRole")
		require.Equal(role, unmarshaled, "marshal and unmarshal should result in identity")
	}

	// Make sure invalid roles return appropriate string representation.
	invalidRoles := []SignerRole{
		SignerUnknown,
		SignerRole(6),
		SignerRole(-1),
	}
	for _, role := range invalidRoles {
		require.Equal("[unknown signer role]", role.String())
	}

	// Make sure invalid role string representations can't be unmarshaled.
	invalidRolesStr := []string{
		SignerUnknown.String(),
		"foo",
		"bar",
	}
	for _, roleStr := range invalidRolesStr {
		var role SignerRole
		err := role.UnmarshalText([]byte(roleStr))
		require.EqualError(err, "signature: invalid signer role: "+roleStr, "unmarshal invalid SignerRole should error")
	}
}
