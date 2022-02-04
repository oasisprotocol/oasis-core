package abci

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
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
	nSubs := len(md.subscriptions[kind])
	if nSubs == 0 {
		return nil, api.ErrNoSubscribers
	}

	var result interface{}
	var errs error
	for _, ms := range md.subscriptions[kind] {
		if resp, err := ms.ExecuteMessage(ctx, kind, msg); err != nil {
			errs = multierror.Append(errs, err)
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
	if errs != nil {
		return nil, errs
	}
	return result, nil
}
