package host

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
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
		case body.WorkerRuntimeCallBatchRequest != nil:
			rq := body.WorkerRuntimeCallBatchRequest

			var stateRoot hash.Hash
			stateRoot.From(rq.Calls)

			ch <- &protocol.Body{WorkerRuntimeCallBatchResponse: &protocol.WorkerRuntimeCallBatchResponse{
				Batch: protocol.ComputedBatch{
					Outputs:      rq.Calls,
					NewStateRoot: stateRoot,
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
		logger: logging.GetLogger("worker/host/mock"),
	}
	return host, nil
}
