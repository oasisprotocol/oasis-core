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

	blkCh, blkSub, err := t.WatchBlocks(ctx)
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
			filter := NewEventFilter(svd.EventType(), query)
			handler := newEventHandler(filter, evCh)
			subscriber := newEventSubscriber(query, t.node.EventBus())

			wg.Go(func() {
				if err := subscriber.process(ctx, handler.handle); err != nil {
					t.Logger.Error("event processing failed", "err", err)
				}
			})
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
	filter *EventFilter
	evCh   chan<- annotatedEvent
}

func newEventHandler(filter *EventFilter, evCh chan<- annotatedEvent) *eventHandler {
	return &eventHandler{
		filter: filter,
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
	// Skip all events not matching the initial query. This is required as we get all
	// events not only those matching the query so we need to do a separate pass.
	for _, ev := range h.filter.Apply(events) {
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

// EventFilter filters events based on the event type and a list of queries.
//
// The filter is not safe for concurrent use.
type EventFilter struct {
	eventType string
	queries   []cmtpubsub.Query
}

// NewEventFilter creates a new event filter.
func NewEventFilter(eventType string, queries ...cmtpubsub.Query) *EventFilter {
	return &EventFilter{
		eventType: eventType,
		queries:   queries,
	}
}

// Apply filters and returns the subset of events that match the event type
// and satisfy at least one of the provided queries.
func (f *EventFilter) Apply(events []cmtabcitypes.Event) []cmtabcitypes.Event {
	filtered := make([]cmtabcitypes.Event, 0, len(events))
	for _, event := range events {
		if f.Matches(event) {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

// Matches checks if an event matches the specified type and any of the queries.
func (f *EventFilter) Matches(event cmtabcitypes.Event) bool {
	if event.GetType() != f.eventType {
		return false
	}

	tagMap := make(map[string][]string)
	for _, attr := range event.Attributes {
		tag := fmt.Sprintf("%s.%s", event.Type, attr.Key)
		tagMap[tag] = append(tagMap[tag], attr.Value)
	}

	for _, query := range f.queries {
		if matched, _ := query.Matches(tagMap); matched {
			return true
		}
	}

	return false
}

// Add appends a new query to the list of queries.
func (f *EventFilter) Add(query cmtpubsub.Query) {
	f.queries = append(f.queries, query)
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
