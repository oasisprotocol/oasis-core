// Package mock implements a mock runtime host useful for tests.
package mock

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

type provisioner struct {
}

// Implements host.Provisioner.
func (p *provisioner) NewRuntime(ctx context.Context, cfg host.Config) (host.Runtime, error) {
	r := &runtime{
		runtimeID: cfg.RuntimeID,
		notifier:  pubsub.NewBroker(false),
	}
	return r, nil
}

type runtime struct {
	runtimeID common.Namespace

	notifier *pubsub.Broker
}

// Implements host.Runtime.
func (r *runtime) ID() common.Namespace {
	return r.runtimeID
}

// Implements host.Runtime.
func (r *runtime) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	switch {
	case body.RuntimeExecuteTxBatchRequest != nil:
		rq := body.RuntimeExecuteTxBatchRequest

		tags := transaction.Tags{
			transaction.Tag{Key: []byte("txn_foo"), Value: []byte("txn_bar")},
		}

		emptyRoot := mkvsNode.Root{
			Namespace: rq.Block.Header.Namespace,
			Version:   rq.Block.Header.Round + 1,
		}
		emptyRoot.Hash.Empty()

		tree := transaction.NewTree(nil, emptyRoot)
		defer tree.Close()

		for i := 0; i < len(rq.Inputs); i++ {
			err := tree.AddTransaction(ctx, transaction.Transaction{
				Input:  rq.Inputs[0],
				Output: rq.Inputs[0],
			}, tags)
			if err != nil {
				return nil, fmt.Errorf("(mock) failed to create I/O tree: %w", err)
			}
		}
		ioWriteLog, ioRoot, err := tree.Commit(ctx)
		if err != nil {
			return nil, fmt.Errorf("(mock) failed to create I/O tree: %w", err)
		}

		var stateRoot, msgsHash hash.Hash
		stateRoot.Empty()
		msgsHash.Empty()

		return &protocol.Body{RuntimeExecuteTxBatchResponse: &protocol.RuntimeExecuteTxBatchResponse{
			Batch: protocol.ComputedBatch{
				Header: commitment.ComputeResultsHeader{
					Round:        rq.Block.Header.Round + 1,
					PreviousHash: rq.Block.Header.EncodedHash(),
					IORoot:       &ioRoot,
					StateRoot:    &stateRoot,
					MessagesHash: &msgsHash,
				},
				IOWriteLog: ioWriteLog,
			},
			// No RakSig in mock response.
		}}, nil
	default:
		return nil, fmt.Errorf("(mock) method not supported")
	}
}

// Implements host.Runtime.
func (r *runtime) WatchEvents(ctx context.Context) (<-chan *host.Event, pubsub.ClosableSubscription, error) {
	typedCh := make(chan *host.Event)
	sub := r.notifier.Subscribe()
	sub.Unwrap(typedCh)

	return typedCh, sub, nil
}

// Implements host.Runtime.
func (r *runtime) Start() error {
	r.notifier.Broadcast(&host.Event{
		Started: &host.StartedEvent{},
	})
	return nil
}

// Implements host.Runtime.
func (r *runtime) Abort(ctx context.Context, force bool) error {
	return nil
}

// Implements host.Runtime.
func (r *runtime) Stop() {
	r.notifier.Broadcast(&host.Event{
		Stopped: &host.StoppedEvent{},
	})
}

// New creates a new mock runtime provisioner useful for tests.
func New() host.Provisioner {
	return &provisioner{}
}
