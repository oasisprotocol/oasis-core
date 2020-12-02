package abci

import (
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
func (md *messageDispatcher) Publish(ctx *api.Context, kind, msg interface{}) error {
	if len(md.subscriptions[kind]) == 0 {
		return api.ErrNoSubscribers
	}

	var errs error
	for _, ms := range md.subscriptions[kind] {
		if err := ms.ExecuteMessage(ctx, kind, msg); err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}
