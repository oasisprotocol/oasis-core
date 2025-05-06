package full

import (
	"context"
	"fmt"
	"sync"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
)

// serviceClientWorker manages block and event notifications for all service clients.
func (t *fullService) serviceClientWorker(ctx context.Context, svc api.ServiceClient) {
	svd := svc.ServiceDescriptor()
	if svd == nil {
		// Some services don't actually need a worker.
		return
	}

	logger := t.Logger.With("service", svd.Name())
	logger.Info("starting event dispatcher")

	blkCh, blkSub, err := t.WatchCometBFTBlocks()
	if err != nil {
		logger.Error("failed to subscribe to cometbft blocks, not starting",
			"err", err,
		)
		return
	}
	defer blkSub.Close()

	var wg sync.WaitGroup
	defer wg.Wait()

	// Service client event loop.
	evCh := make(chan annotatedEvent, 1)
	for {
		select {
		case <-ctx.Done():
			return
		case query := <-svd.Queries():
			subscriber := newEventSubscriber(query, t.node.EventBus())
			handler := newEventHandler(query, svd.EventType(), evCh)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := subscriber.process(ctx, handler.handle); err != nil {
					t.Logger.Error("event processing failed", "err", err)
				}
			}()
		case blk, ok := <-blkCh:
			if !ok {
				return
			}
			if err := svc.DeliverHeight(ctx, blk.Height); err != nil {
				logger.Error("failed to deliver block height to service client", "err", err)
			}
		case ev := <-evCh:
			if err := svc.DeliverEvent(ctx, ev.height, ev.tx, &ev.ev); err != nil {
				logger.Error("failed to deliver event to service client", "err", err)
			}
		}
	}
}

type annotatedEvent struct {
	height int64
	tx     cmttypes.Tx
	ev     cmtabcitypes.Event
}

type eventHandler struct {
	query cmtpubsub.Query

	evType string
	evCh   chan<- annotatedEvent
}

func newEventHandler(query cmtpubsub.Query, evType string, evCh chan<- annotatedEvent) *eventHandler {
	return &eventHandler{
		query:  query,
		evType: evType,
		evCh:   evCh,
	}
}

func (h *eventHandler) handle(ctx context.Context, msg cmtpubsub.Message) {
	switch ev := msg.Data().(type) {
	case cmttypes.EventDataNewBlockHeader:
		h.handleBlockEvent(ctx, ev)
	case cmttypes.EventDataTx:
		h.handleTxEvent(ctx, ev)
	default:
	}
}

func (h *eventHandler) handleBlockEvent(ctx context.Context, ev cmttypes.EventDataNewBlockHeader) {
	h.deliverEvents(ctx, ev.Header.Height, nil, ev.ResultBeginBlock.GetEvents())
	h.deliverEvents(ctx, ev.Header.Height, nil, ev.ResultEndBlock.GetEvents())
}

func (h *eventHandler) handleTxEvent(ctx context.Context, ev cmttypes.EventDataTx) {
	h.deliverEvents(ctx, ev.Height, ev.Tx, ev.Result.Events)
}

func (h *eventHandler) deliverEvents(ctx context.Context, height int64, tx cmttypes.Tx, events []cmtabcitypes.Event) {
	for _, ev := range events {
		// Skip all events not from the target service.
		if ev.GetType() != h.evType {
			continue
		}
		// Skip all events not matching the initial query. This is required as we get all
		// events not only those matching the query so we need to do a separate pass.
		tagMap := make(map[string][]string)
		for _, attr := range ev.Attributes {
			compositeTag := fmt.Sprintf("%s.%s", ev.Type, attr.Key)
			tagMap[compositeTag] = append(tagMap[compositeTag], attr.Value)
		}
		if matches, _ := h.query.Matches(tagMap); !matches {
			continue
		}

		ev := annotatedEvent{
			height: height,
			tx:     tx,
			ev:     ev,
		}
		select {
		case h.evCh <- ev:
		case <-ctx.Done():
			return
		}
	}
}

type eventSubscriber struct {
	query    cmtpubsub.Query
	eventBus *cmttypes.EventBus
}

func newEventSubscriber(query cmtpubsub.Query, eventBus *cmttypes.EventBus) *eventSubscriber {
	return &eventSubscriber{
		query:    query,
		eventBus: eventBus,
	}
}

func (s *eventSubscriber) process(ctx context.Context, handle func(ctx context.Context, msg cmtpubsub.Message)) error {
	sub, err := s.eventBus.SubscribeUnbuffered(ctx, tmSubscriberID, s.query)
	if err != nil {
		return fmt.Errorf("failed to subscribe to events: %w", err)
	}
	// Oh yes, this can actually return a nil subscription even though the error was also
	// nil if the node is just shutting down.
	if sub == (*cmtpubsub.Subscription)(nil) {
		return nil
	}
	defer s.eventBus.Unsubscribe(ctx, tmSubscriberID, s.query) // nolint: errcheck

	for {
		select {
		// Should not return on ctx.Done() as that could lead to a deadlock.
		case <-sub.Cancelled():
			return nil
		case v := <-sub.Out():
			handle(ctx, v)
		}
	}
}
