package host

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ias"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

const recvTimeout = 5 * time.Second

var (
	envWorkerHostWorkerBinary  = os.Getenv("EKIDEN_TEST_WORKER_HOST_WORKER_BINARY")
	envWorkerHostRuntimeBinary = os.Getenv("EKIDEN_TEST_WORKER_HOST_RUNTIME_BINARY")
	envWorkerHostTEE           = os.Getenv("EKIDEN_TEST_WORKER_HOST_TEE")
)

type mockHostHandler struct{}

func (h *mockHostHandler) Handle(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	return nil, errors.New("method not supported")
}

func skipIfMissingDeps(t *testing.T) {
	// Skip test if there is no bubblewrap binary available.
	if _, err := os.Stat(workerBubblewrapBinary); os.IsNotExist(err) {
		t.Skip("skipping as bubblewrap not available")
	}

	// Skip test if there is no worker binary configured.
	if envWorkerHostWorkerBinary == "" {
		t.Skip("skipping as EKIDEN_TEST_WORKER_HOST_WORKER_BINARY is not set")
	}

	// Skip test if there is no runtime configured.
	if envWorkerHostRuntimeBinary == "" {
		t.Skip("skipping as EKIDEN_TEST_WORKER_HOST_RUNTIME_BINARY is not set")
	}
}

func TestSandboxedHost(t *testing.T) {
	skipIfMissingDeps(t)

	if testing.Verbose() {
		// Initialize logging to aid debugging.
		_ = logging.Initialize(os.Stdout, logging.FmtLogfmt, logging.LevelDebug, map[string]logging.Level{})
	}

	// Initialize sandboxed host.
	var tee node.TEEHardware
	switch strings.ToLower(envWorkerHostTEE) {
	case "intel-sgx":
		tee = node.TEEHardwareIntelSGX
	default:
	}

	ias, err := ias.New(nil)
	require.NoError(t, err, "ias.New")

	// Create host with sandbox disabled.
	host, err := NewSandboxedHost(
		"test_worker",
		envWorkerHostWorkerBinary,
		envWorkerHostRuntimeBinary,
		make(map[string]ProxySpecification),
		tee,
		ias,
		&mockHostHandler{},
		nil,
		true,
	)
	require.NoError(t, err, "NewSandboxedHost")

	t.Run("WithNoSandbox", func(t *testing.T) {
		testSandboxedHost(t, host)
	})

	// Create host with sandbox enabled.
	host, err = NewSandboxedHost(
		"test_worker",
		envWorkerHostWorkerBinary,
		envWorkerHostRuntimeBinary,
		make(map[string]ProxySpecification),
		tee,
		ias,
		&mockHostHandler{},
		nil,
		false,
	)
	require.NoError(t, err, "NewSandboxedHost")

	t.Run("WithSandbox", func(t *testing.T) {
		testSandboxedHost(t, host)
	})
}

func testSandboxedHost(t *testing.T, host Host) {
	// Start the host.
	err := host.Start()
	require.NoError(t, err, "Start")
	defer func() {
		host.Stop()
		<-host.Quit()
	}()

	// Run actual test cases.

	t.Run("WaitForCapabilityTEE", func(t *testing.T) {
		testWaitForCapabilityTEE(t, host)
	})

	t.Run("WaitForVersion", func(t *testing.T) {
		testWaitForVersion(t, host)
	})

	t.Run("SimpleRequest", func(t *testing.T) {
		testSimpleRequest(t, host)
	})

	t.Run("InterruptWorker", func(t *testing.T) {
		testInterruptWorker(t, host)
	})

	t.Run("CheckTxRequest", func(t *testing.T) {
		testCheckTxRequest(t, host)
	})
}

func testWaitForCapabilityTEE(t *testing.T, host Host) {
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	cap, err := host.WaitForCapabilityTEE(ctx)
	require.NoError(t, err, "WaitForCapabilityTEE")
	switch host.(*sandboxedHost).teeHardware {
	case node.TEEHardwareIntelSGX:
		require.NotNil(t, cap, "capabilities should not be nil")
		require.Equal(t, node.TEEHardwareIntelSGX, cap.Hardware, "TEE hardware should be Intel SGX")
	default:
		require.Nil(t, cap, "capabilites should be nil")
	}
}

func testWaitForVersion(t *testing.T, host Host) {
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	v, err := host.WaitForRuntimeVersion(ctx)
	require.NoError(t, err, "WaitForVersion")
	require.NotNil(t, v, "version should not be nil")
}

func testSimpleRequest(t *testing.T, host Host) {
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	rspCh, err := host.MakeRequest(ctx, &protocol.Body{WorkerPingRequest: &protocol.Empty{}})
	require.NoError(t, err, "MakeRequest")

	select {
	case rsp := <-rspCh:
		require.NotNil(t, rsp, "worker channel should not be closed while waiting for response")
		require.NotNil(t, rsp.Empty, "worker response to ping should return an Empty body")
	case <-ctx.Done():
		require.Fail(t, "timed out while waiting for response from worker")
	}
}

// NOTE: This test only works with Ekiden's simple-keyvalue runtime.
func testCheckTxRequest(t *testing.T, host Host) {
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	type KeyValue struct {
		Key   string `codec:"key"`
		Value string `codec:"value"`
	}

	// TxnCall is meant for deserializing CBOR of the corresponding Rust struct and is specific
	// to the simple-keyvalue runtime.
	type TxnCall struct {
		Method string   `codec:"method"`
		Args   KeyValue `codec:"args"`
	}

	// Create a batch of transactions, including a valid one, an invalid one and one where the
	// method is missing.
	txnCallValid := TxnCall{Method: "insert", Args: KeyValue{Key: "foo", Value: "bar"}}
	// The simple-keyvalue runtime's insert method accepts values <= 128 bytes.
	tooBigValue := string(make([]byte, 129))
	txnCallInvalid := TxnCall{Method: "insert", Args: KeyValue{Key: "foo", Value: tooBigValue}}
	txnCallMissing := TxnCall{Method: "missing_method", Args: KeyValue{Key: "foo", Value: "bar"}}
	batch := transaction.Batch([][]byte{cbor.Marshal(&txnCallValid), cbor.Marshal(&txnCallInvalid), cbor.Marshal(&txnCallMissing)})

	rspCh, err := host.MakeRequest(ctx, &protocol.Body{
		WorkerCheckTxBatchRequest: &protocol.WorkerCheckTxBatchRequest{
			Inputs: batch,
		},
	})
	require.NoError(t, err, "MakeRequest")

	select {
	case rsp := <-rspCh:
		require.NotNil(t, rsp, "worker channel should not be closed while waiting for response")
		require.NotNil(t, rsp.WorkerCheckTxBatchResponse.Results, "worker should respond to check tx call")
		require.Len(t, rsp.WorkerCheckTxBatchResponse.Results, 3, "worker should return a check tx call result for each txn")

		txnOutputValidRaw := rsp.WorkerCheckTxBatchResponse.Results[0]
		var txnOutputValid transaction.TxnOutput
		cbor.MustUnmarshal(txnOutputValidRaw, &txnOutputValid)
		require.NotNil(t, txnOutputValid.Success, "valid tx call should return success")
		require.Nil(t, txnOutputValid.Error, "valid tx call should not return error")

		txnOutputInvalidRaw := rsp.WorkerCheckTxBatchResponse.Results[1]
		var txnOutputInvalid transaction.TxnOutput
		cbor.MustUnmarshal(txnOutputInvalidRaw, &txnOutputInvalid)
		require.Nil(t, txnOutputInvalid.Success, "invalid tx call should not return success")
		require.NotNil(t, txnOutputInvalid.Error, "invalid tx call should return error")
		require.Regexp(t, "^Value too big to be inserted", *txnOutputInvalid.Error, "invalid tx call should indicate that method was not found")

		txnOutputMissingRaw := rsp.WorkerCheckTxBatchResponse.Results[2]
		var txnOutputMissing transaction.TxnOutput
		cbor.MustUnmarshal(txnOutputMissingRaw, &txnOutputMissing)
		require.Nil(t, txnOutputMissing.Success, "tx call for a missing method should not return success")
		require.NotNil(t, txnOutputMissing.Error, "tx call for a missing method should return error")
		require.Regexp(t, "^method not found", *txnOutputMissing.Error, "tx call for a missing method should indicate that method was not found")

	case <-ctx.Done():
		require.Fail(t, "timed out while waiting for response from worker")
	}
}

func testInterruptWorker(t *testing.T, host Host) {
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	err := host.InterruptWorker(ctx)
	require.NoError(t, err, "InterruptWorker")

	testSimpleRequest(t, host)
}
