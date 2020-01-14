package host

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	urkelNode "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/worker/common/host/protocol"
)

var (
	_ Host = (*mockHost)(nil)
)

// BackendMock is the name of the mock backend.
const BackendMock = "mock"

// MockHost is a mock worker Host used in tests.
type mockHost struct {
	BaseHost

	quitCh chan struct{}

	logger *logging.Logger
}

func (h *mockHost) Name() string {
	return "mock worker host"
}

func (h *mockHost) Start() error {
	h.logger.Info("starting mock worker host")
	return nil
}

func (h *mockHost) Stop() {
	close(h.quitCh)
}

func (h *mockHost) Quit() <-chan struct{} {
	return h.quitCh
}

func (h *mockHost) Cleanup() {
}

func (h *mockHost) MakeRequest(ctx context.Context, body *protocol.Body) (<-chan *protocol.Body, error) {
	ch := make(chan *protocol.Body)
	go func() {
		defer close(ch)

		switch {
		case body.WorkerExecuteTxBatchRequest != nil:
			rq := body.WorkerExecuteTxBatchRequest

			tags := transaction.Tags{
				transaction.Tag{Key: []byte("txn_foo"), Value: []byte("txn_bar")},
			}

			emptyRoot := urkelNode.Root{
				Namespace: rq.Block.Header.Namespace,
				Round:     rq.Block.Header.Round + 1,
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
					ch <- &protocol.Body{Error: &protocol.Error{Message: "(mock) failed to create I/O tree"}}
					return
				}
			}
			ioWriteLog, ioRoot, err := tree.Commit(ctx)
			if err != nil {
				ch <- &protocol.Body{Error: &protocol.Error{Message: "(mock) failed to create I/O tree"}}
				return
			}

			var stateRoot hash.Hash
			stateRoot.Empty()

			ch <- &protocol.Body{WorkerExecuteTxBatchResponse: &protocol.WorkerExecuteTxBatchResponse{
				Batch: protocol.ComputedBatch{
					Header: commitment.ComputeResultsHeader{
						PreviousHash: rq.Block.Header.EncodedHash(),
						IORoot:       ioRoot,
						StateRoot:    stateRoot,
					},
					IOWriteLog: ioWriteLog,
				},
				// No RakSig in mock reponse.
			}}
		default:
			ch <- &protocol.Body{Error: &protocol.Error{Message: "(mock) method not supported"}}
		}
	}()

	return ch, nil
}

func (h *mockHost) InterruptWorker(ctx context.Context) error {
	return nil
}

func (h *mockHost) WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error) {
	ch := make(chan *Event)
	ctx, sub := pubsub.NewContextSubscription(ctx)
	go func() {
		defer close(ch)
		// Generate a mock worker host started event.
		ch <- &Event{
			Started: &StartedEvent{},
		}
		<-ctx.Done()
	}()
	return ch, sub, nil
}

// NewMockHost creates a new mock worker host.
func NewMockHost() (Host, error) {
	host := &mockHost{
		quitCh: make(chan struct{}),
		logger: logging.GetLogger("worker/common/host/mock"),
	}
	host.BaseHost = BaseHost{Host: host}

	return host, nil
}
