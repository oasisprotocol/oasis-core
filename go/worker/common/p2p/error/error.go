// Package error exists only to break an import loop.
package error

import (
	"context"
	"errors"

	"github.com/cenkalti/backoff/v4"
)

// Permanent wraps an error returned by various handler functions to
// suppress retry.
func Permanent(err error) error {
	return backoff.Permanent(err)
}

// IsPermanent returns true iff the error is a permanent p2p message
// handler error.
func IsPermanent(err error) bool {
	if errors.Is(err, context.Canceled) {
		// Context cancellation errors should not count as permanent for P2P dispatch. This is
		// because the cancelled context may be due to the round advancing in which case dispatch
		// should actually be retried.
		return false
	}
	_, ok := (err).(*backoff.PermanentError)
	return ok
}
