package peermgmt

import (
	"time"

	"github.com/cenkalti/backoff/v4"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
)

type backOff struct {
	bo      *backoff.ExponentialBackOff
	nextTry time.Time
}

func newBackOff(nextTry time.Time, initialInterval time.Duration, maxInterval time.Duration) *backOff {
	bo := cmnBackoff.NewExponentialBackOff()
	bo.InitialInterval = initialInterval
	bo.MaxInterval = maxInterval
	bo.Reset()

	return &backOff{
		bo:      bo,
		nextTry: nextTry,
	}
}

func (b *backOff) check(t time.Time) bool {
	return !t.Before(b.nextTry)
}

func (b *backOff) extend() {
	b.nextTry = time.Now().Add(b.bo.NextBackOff())
}

func (b *backOff) reset() {
	b.bo.Reset()
	b.nextTry = time.Now()
}
