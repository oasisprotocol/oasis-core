package abci

import (
	"errors"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
)

var _ api.MessageDispatcher = (*messageDispatcher)(nil)

type messageDispatcher struct {
	subscriptions map[interface{}][]api.MessageSubscriber
}

// Implements api.MessageDispatcher.
func (md *messageDispatcher) Subscribe(kind interface{}, ms api.MessageSubscriber) {
	if md.subscriptions == nil {
		md.subscriptions = make(map[interface{}][]api.MessageSubscriber)
	}
	md.subscriptions[kind] = append(md.subscriptions[kind], ms)
}

// Implements api.MessageDispatcher.
func (md *messageDispatcher) Publish(ctx *api.Context, kind, msg interface{}) (interface{}, error) {
	var (
		result         interface{}
		errs           error
		numSubscribers int
	)
	for _, ms := range md.subscriptions[kind] {
		// Check whether the subscriber can be toggled.
		if togMs, ok := ms.(api.TogglableMessageSubscriber); ok {
			enabled, err := togMs.Enabled(ctx)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}
			if !enabled {
				// If a subscriber is not enabled, skip it during dispatch.
				continue
			}
		}
		numSubscribers++

		// Deliver the message.
		if resp, err := ms.ExecuteMessage(ctx, kind, msg); err != nil {
			errs = errors.Join(errs, err)
		} else {
			switch {
			case resp != nil && result == nil:
				// Non-nil result.
				result = resp
			case resp != nil && result != nil:
				// Multiple non-nil results, this is unexpected and unsupported by the pub-sub interface at this time.
				panic(fmt.Sprintf("unexpected result: got: %d, previous result: %d", resp, result))
			default:
			}
		}
	}
	if numSubscribers == 0 {
		return nil, api.ErrNoSubscribers
	}
	if errs != nil {
		return nil, errs
	}
	return result, nil
}
