package full

import (
	"context"
	"fmt"
	"reflect"

	"github.com/eapache/channels"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmpubsub "github.com/tendermint/tendermint/libs/pubsub"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
)

// serviceClientWorker manages block and event notifications for all service clients.
func (t *fullService) serviceClientWorker(ctx context.Context, svc api.ServiceClient) {
	defer t.serviceClientsWg.Done()

	sd := svc.ServiceDescriptor()
	if sd == nil {
		// Some services don't actually need a worker.
		return
	}

	logger := t.Logger.With("service", sd.Name())
	logger.Info("starting event dispatcher")

	var (
		cases   []reflect.SelectCase
		queries []tmpubsub.Query
	)
	// Context cancellation.
	const indexCtx = 0
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	})
	queries = append(queries, nil)
	// General query for new block headers.
	newBlockCh, newBlockSub := t.WatchTendermintBlocks()
	defer newBlockSub.Close()

	const indexNewBlock = 1
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(newBlockCh),
	})
	queries = append(queries, nil)
	// Query update.
	const indexQueries = 2
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(sd.Queries()),
	})
	queries = append(queries, nil)
	// Commands.
	const indexCommands = 3
	cases = append(cases, reflect.SelectCase{
		Dir: reflect.SelectRecv,
		// Initially, start with a nil channel and only start looking into commands after we see a
		// block from the consensus backend.
		Chan: reflect.ValueOf(nil),
	})
	queries = append(queries, nil)

	// Service client event loop.
	var height int64
	for {
		chosen, recv, recvOk := reflect.Select(cases)
		if !recvOk {
			// Replace closed channels with nil to avoid needless wakeups.
			cases[chosen].Chan = reflect.ValueOf(nil)
			if chosen != indexCtx {
				continue
			}
		}
		switch chosen {
		case indexCtx:
			return
		case indexQueries:
			// Subscribe to new query.
			query := recv.Interface().(tmpubsub.Query)

			logger.Debug("subscribing to new query",
				"query", query,
			)

			sub, err := t.node.EventBus().SubscribeUnbuffered(ctx, tmSubscriberID, query)
			if err != nil {
				logger.Error("failed to subscribe to service events",
					"err", err,
				)
				continue
			}
			// Oh yes, this can actually return a nil subscription even though the error was also
			// nil if the node is just shutting down.
			if sub == (*tmpubsub.Subscription)(nil) {
				continue
			}

			// Transform events.
			buffer := channels.NewInfiniteChannel()
			go func() {
				defer t.node.EventBus().Unsubscribe(ctx, tmSubscriberID, query) // nolint: errcheck
				defer buffer.Close()

				for {
					select {
					// Should not return on ctx.Done() as that could lead to a deadlock.
					case <-sub.Cancelled():
						// Subscription cancelled.
						return
					case v := <-sub.Out():
						// Received an event.
						switch ev := v.Data().(type) {
						case tmtypes.EventDataNewBlockHeader:
							buffer.In() <- &api.ServiceEvent{Block: &ev}
						case tmtypes.EventDataTx:
							buffer.In() <- &api.ServiceEvent{Tx: &ev}
						default:
						}
					}
				}
			}()

			cases = append(cases, reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(buffer.Out()),
			})
			queries = append(queries, query)
		case indexCommands:
			// New command.
			if err := svc.DeliverCommand(ctx, height, recv.Interface()); err != nil {
				logger.Error("failed to deliver command to service client",
					"err", err,
				)
				continue
			}
		case indexNewBlock:
			// New block.
			if height == 0 {
				// Seen a block, now we are ready to process commands.
				cases[indexCommands].Chan = reflect.ValueOf(sd.Commands())
			}
			height = recv.Interface().(*tmtypes.Block).Header.Height

			if err := svc.DeliverBlock(ctx, height); err != nil {
				logger.Error("failed to deliver block notification to service client",
					"err", err,
				)
				continue
			}
		default:
			// New service client event.
			ev := recv.Interface().(*api.ServiceEvent)
			var (
				tx       tmtypes.Tx
				tmEvents []tmabcitypes.Event
			)
			switch {
			case ev.Block != nil:
				height = ev.Block.Header.Height
				tmEvents = append([]tmabcitypes.Event{}, ev.Block.ResultBeginBlock.GetEvents()...)
				tmEvents = append(tmEvents, ev.Block.ResultEndBlock.GetEvents()...)
			case ev.Tx != nil:
				height = ev.Tx.Height
				tx = ev.Tx.Tx
				tmEvents = ev.Tx.Result.Events
			default:
				logger.Warn("unknown event",
					"ev", fmt.Sprintf("%+v", ev),
				)
				continue
			}

			// Deliver all events.
			query := queries[chosen]
			for i, tmEv := range tmEvents {
				// Skip all events not from the target service.
				if tmEv.GetType() != sd.EventType() {
					continue
				}
				// Skip all events not matching the initial query. This is required as we get all
				// events not only those matching the query so we need to do a separate pass.
				tagMap := make(map[string][]string)
				for _, attr := range tmEv.Attributes {
					compositeTag := fmt.Sprintf("%s.%s", tmEv.Type, string(attr.Key))
					tagMap[compositeTag] = append(tagMap[compositeTag], string(attr.Value))
				}
				if matches, _ := query.Matches(tagMap); !matches {
					continue
				}

				if err := svc.DeliverEvent(ctx, height, tx, &tmEvents[i]); err != nil {
					logger.Error("failed to deliver event to service client",
						"err", err,
					)
					continue
				}
			}
		}
	}
}
