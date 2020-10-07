// Package error exists only to break an import loop.
package error

import (
	"context"
	"errors"
	"fmt"

	"github.com/cenkalti/backoff/v4"
)

// relayError signals that the message should be relayed.
type relayError struct {
	error
}

func (e *relayError) Unwrap() error {
	return e.error
}

func (e *relayError) Is(target error) bool {
	_, ok := target.(*relayError)
	return ok
}

// Relayable wraps an error returned by various handler functions to mark the
// error as relayable.
func Relayable(err error) error {
	return &relayError{err}
}

// IsRelayable returns true if the error is relayable.
func IsRelayable(err error) bool {
	return errors.Is(err, &relayError{})
}

// ShouldRelay returns if true the message should be relayed despite the error.
//
// In adition to all non-permanent errors, errors that are explicitly marked as
// relayable should be relayed.
func ShouldRelay(err error) bool {
	return !IsPermanent(err) || IsRelayable(err)
}

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
	var e *backoff.PermanentError
	return errors.As(err, &e)
}

// EnsurePermanent ensures an error will be correctly treated as (non-)permanent
// by `cenkalti/backoff/v4`.
//
// Note: `IsPermanent` notion of a permanent error differs from the `cenkalti/backoff/v4`:
// - it special cases `context.Canceled`
// - it correctly handles wrapped permanent errors
func EnsurePermanent(err error) error {
	// XXX: once https://github.com/cenkalti/backoff/issues/107 is addressed
	// we only need to handle the `context.Canceled` case.
	upstreamCheck := func(err error) bool {
		// https://github.com/cenkalti/backoff/blob/31cc31bb63269a3c813d1f26e0ab058452b7d803/retry.go#L56-L58
		if _, ok := err.(*backoff.PermanentError); ok {
			return true
		}
		return false
	}

	if IsPermanent(err) == upstreamCheck(err) {
		return err
	}

	switch {
	case IsPermanent(err):
		// In case we consider error as permanent, re-wrap it to ensure
		// `cenkalti/backoff/v4` will also treat it as such.
		e := backoff.Permanent(err)
		return e
	default:
		// In case we don't consider the error permanent, but upstream does, wrap it.
		return fmt.Errorf("non-permanent: %w", err)
	}
}
