package error

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/require"
)

func TestRelayError(t *testing.T) {
	require := require.New(t)

	err := io.EOF
	require.False(IsRelayable(err), "EOF error should not be relayed")
	require.True(IsRelayable(Relayable(err)), "wrapped EOF error should be relayed")
}

func TestPermanentError(t *testing.T) {
	require := require.New(t)

	require.False(IsPermanent(context.Canceled), "context.Canceled should be retried")
	require.False(IsPermanent(Permanent(context.Canceled)), "wrapped context.Canceled should be retried")
	require.False(IsPermanent(io.EOF), "EOF error should be retried")
	require.True(IsPermanent(Permanent(io.EOF)), "wrapped EOF error should not be retried")
}

func TestRelayPermanentError(t *testing.T) {
	require := require.New(t)

	err := io.EOF
	require.True(IsRelayable(Relayable(Permanent(err))), "wrapped EOF error should be relayed")
	require.True(IsRelayable(Permanent(Relayable(err))), "wrapped EOF error should be relayed")

	require.True(IsPermanent(Relayable(Permanent(err))), "wrapped EOF error should be permanent")
	require.True(IsPermanent(Permanent(Relayable(err))), "wrapped EOF error should be permanent")
}

func TestShouldRelay(t *testing.T) {
	require := require.New(t)

	require.True(ShouldRelay(io.EOF), "normal error should be relayed")
	require.False(ShouldRelay(Permanent(io.EOF)), "permanent error should not be relayed")
	require.True(ShouldRelay(Permanent(Relayable(io.EOF))), "relayable permanent errors should be relayed")
	require.True(ShouldRelay(Relayable(Permanent(io.EOF))), "relayable permanent errors should be relayed")
}

func TestEnsurePermanent(t *testing.T) {
	require := require.New(t)

	ctx := context.Background()

	ensureRetries := func(test string, shouldRetry bool, f func() error) {
		numRetries := -1

		off := backoff.WithMaxRetries(backoff.NewConstantBackOff(50*time.Millisecond), 2)
		bctx := backoff.WithContext(off, ctx)
		_ = backoff.Retry(func() error {
			numRetries++
			return f()
		}, bctx)

		if shouldRetry && numRetries == 0 {
			require.FailNow("backoff should have retried", test)
		}

		if !shouldRetry && numRetries > 0 {
			require.FailNow("backoff should not have retried", test)
		}
	}

	for _, testCase := range []struct {
		name        string
		testF       func() error
		shouldRetry bool
	}{
		{
			"nil test",
			func() error {
				return nil
			},
			false,
		},
		{
			"io.EOF",
			func() error {
				return io.EOF
			},
			true,
		},
		{
			"Relayable(Permanent(io.EOF))",
			func() error {
				return Relayable(Permanent(io.EOF))
			},
			false,
		},
		{
			// This case is treated as permanent by backoff, but we treat it as
			// a non-permanent error.
			"Permanent(context.Canceled)",
			func() error {
				return Permanent(context.Canceled)
			},
			false,
		},
		{
			// This case tests EnsurePermanent on the previous test case.
			"EnsurePermanent(Permanent(context.Canceled))",
			func() error {
				return EnsurePermanent(Permanent(context.Canceled))
			},
			true,
		},
	} {
		ensureRetries(testCase.name, testCase.shouldRetry, testCase.testF)
	}
}
