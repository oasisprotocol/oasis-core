// Package error exists only to break an import loop.
package error

import "github.com/cenkalti/backoff/v4"

// Permanent wraps an error returned by various handler functions to
// suppress retry.
func Permanent(err error) error {
	return backoff.Permanent(err)
}

// IsPermanent returns true iff the error is a permanent p2p message
// handler error.
func IsPermanent(err error) bool {
	_, ok := (err).(*backoff.PermanentError)
	return ok
}
