package host

import (
	"context"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtimeMock "github.com/oasislabs/ekiden/go/epochtime/mock"
	storageMemory "github.com/oasislabs/ekiden/go/storage/memory"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/ias"
)

const recvTimeout = 5 * time.Second

var (
	envWorkerHostWorkerBinary  = os.Getenv("EKIDEN_TEST_WORKER_HOST_WORKER_BINARY")
	envWorkerHostRuntimeBinary = os.Getenv("EKIDEN_TEST_WORKER_HOST_RUNTIME_BINARY")
)

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
		_ = logging.Initialize(os.Stdout, logging.LevelDebug, logging.FmtLogfmt)
	}

	// Initialize sandboxed host.
	var runtimeID signature.PublicKey
	runtimeIDRaw, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
	_ = runtimeID.UnmarshalBinary(runtimeIDRaw)

	timeSource := epochtimeMock.New()
	storage := storageMemory.New(timeSource)
	<-storage.Initialized()

	ias, err := ias.New(nil, "")
	require.NoError(t, err, "ias.New")

	// Create host with sandbox disabled.
	host, err := NewSandboxedHost(
		envWorkerHostWorkerBinary,
		envWorkerHostRuntimeBinary,
		runtimeID,
		storage,
		node.TEEHardwareIntelSGX,
		ias,
		nil,
		true,
	)
	require.NoError(t, err, "NewSandboxedHost")

	t.Run("WithNoSandbox", func(t *testing.T) {
		testSandboxedHost(t, host)
	})

	// Create host with sandbox enabled.
	host, err = NewSandboxedHost(
		envWorkerHostWorkerBinary,
		envWorkerHostRuntimeBinary,
		runtimeID,
		storage,
		node.TEEHardwareIntelSGX,
		ias,
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

	t.Run("SimpleRequest", func(t *testing.T) {
		testSimpleRequest(t, host)
	})

	t.Run("InterruptWorker", func(t *testing.T) {
		testInterruptWorker(t, host)
	})
}

func testWaitForCapabilityTEE(t *testing.T, host Host) {
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	cap, err := host.WaitForCapabilityTEE(ctx)
	require.NoError(t, err, "WaitForCapabilityTEE")
	require.NotNil(t, cap, "capabilities should not be nil")
	require.Equal(t, node.TEEHardwareIntelSGX, cap.Hardware, "TEE hardware should be Intel SGX")
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

func testInterruptWorker(t *testing.T, host Host) {
	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	err := host.InterruptWorker(ctx)
	require.NoError(t, err, "InterruptWorker")

	testSimpleRequest(t, host)
}
