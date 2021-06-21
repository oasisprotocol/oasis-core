// Package backoff contains helpers for dealing with backoffs.
package backoff

import "github.com/cenkalti/backoff/v4"

// NewExponentialBackOff creates an instance of ExponentialBackOff using reasonable defaults.
func NewExponentialBackOff() *backoff.ExponentialBackOff {
	boff := backoff.NewExponentialBackOff()
	boff.MaxElapsedTime = 0 // Make sure that the backoff never stops by default.
	return boff
}
