package host

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	urkelNode "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

var (
	_ Host = (*mockHost)(nil)
)

// BackendMock is the name of the mock backend.
const BackendMock = "mock"

// MockHost is a mock worker Host used in tests.
type mockHost struct {
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

			tree, err := transaction.NewTree(ctx, nil, emptyRoot)
			if err != nil {
				ch <- &protocol.Body{Error: &protocol.Error{Message: "(mock) failed to create I/O tree"}}
				return
			}
			defer tree.Close()
			for i := 0; i < len(rq.Inputs); i++ {
				err = tree.AddTransaction(ctx, transaction.Transaction{
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

func (h *mockHost) WaitForCapabilityTEE(ctx context.Context) (*node.CapabilityTEE, error) {
	return nil, nil
}

func (h *mockHost) InterruptWorker(ctx context.Context) error {
	return nil
}

// NewMockHost creates a new mock worker host.
func NewMockHost() (Host, error) {
	host := &mockHost{
		quitCh: make(chan struct{}),
		logger: logging.GetLogger("worker/common/host/mock"),
	}
	return host, nil
}
