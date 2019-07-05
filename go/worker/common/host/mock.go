package host

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
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
		switch {
		case body.WorkerExecuteTxBatchRequest != nil:
			rq := body.WorkerExecuteTxBatchRequest

			tags := []runtime.Tag{
				runtime.Tag{TxnIndex: runtime.TagTxnIndexBlock, Key: []byte("foo"), Value: []byte("bar")},
				runtime.Tag{TxnIndex: 0, Key: []byte("txn_foo"), Value: []byte("txn_bar")},
			}

			tree := urkel.New(nil, nil)
			_ = tree.Insert(ctx, block.IoKeyInputs, rq.Inputs.MarshalCBOR())
			_ = tree.Insert(ctx, block.IoKeyOutputs, rq.Inputs.MarshalCBOR())
			_ = tree.Insert(ctx, block.IoKeyTags, cbor.Marshal(tags))
			ioWriteLog, ioRoot, err := tree.Commit(ctx, rq.Block.Header.Namespace, rq.Block.Header.Round)
			if err != nil {
				ch <- &protocol.Body{Error: &protocol.Error{Message: "(mock) failed to create I/O tree"}}
				break
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

		close(ch)
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
