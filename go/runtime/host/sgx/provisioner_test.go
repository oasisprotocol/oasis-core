package sgx

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	cmnIAS "github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	cmt "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/ias/api"
	iasHttp "github.com/oasisprotocol/oasis-core/go/ias/http"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/tests"
)

// This needs to be large as some runtimes can take a long time to initialize due to remote
// attestation taking a long time.
const recvTimeout = 120 * time.Second

var (
	envRuntimePath       = os.Getenv("OASIS_TEST_RUNTIME_HOST_BUNDLE_PATH")
	envRuntimeLoaderPath = os.Getenv("OASIS_TEST_RUNTIME_HOST_SGX_LOADER_PATH")
)

func skipIfMissingDeps(t *testing.T) {
	// Skip test if there is no runtime configured.
	if envRuntimePath == "" {
		t.Skip("skipping as OASIS_TEST_RUNTIME_HOST_BUNDLE_PATH is not set")
	}

	// Skip test if there is no runtime loader configured.
	if envRuntimeLoaderPath == "" {
		t.Skip("skipping as OASIS_TEST_RUNTIME_HOST_SGX_LOADER_PATH is not set")
	}
}

func TestProvisionerSGX(t *testing.T) {
	const bwrapPath = "/usr/bin/bwrap" // Sensible systems only.

	skipIfMissingDeps(t)

	require := require.New(t)

	bnd, err := bundle.Open(envRuntimePath)
	require.NoError(err, "bundle.Open")

	tmpDir := t.TempDir()
	_, err = bnd.WriteExploded(tmpDir)
	require.NoError(err, "bnd.WriteExploded")

	explodedDataDir := bnd.ExplodedPath(tmpDir, "")

	cfg := host.Config{
		Name: "test-runtime",
		ID:   bnd.Manifest.ID,
	}

	for _, comp := range bnd.Manifest.Components {
		cfg.Components = append(cfg.Components, &bundle.ExplodedComponent{
			Component:       comp,
			ExplodedDataDir: explodedDataDir,
		})
	}

	ias, err := iasHttp.New(&iasHttp.Config{
		SPID:               "9b3085a55a5863f7cc66b380dcad0082",
		QuoteSignatureType: cmnIAS.SignatureUnlinkable,
		DebugIsMock:        true,
	})
	require.NoError(err, "iasHttp.New")

	extraTests := []tests.TestCase{
		{
			Name: "AttestationWorker",
			Fn:   testAttestationWorker,
		},
	}

	t.Run("Naked", func(t *testing.T) {
		tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
			return NewProvisioner(Config{
				HostInfo: &protocol.HostInfo{
					ConsensusBackend:         cmt.BackendName,
					ConsensusProtocolVersion: version.Versions.ConsensusProtocol,
				},
				LoaderPath:            envRuntimeLoaderPath,
				IAS:                   []api.Endpoint{ias},
				RuntimeAttestInterval: 2 * time.Second,
				InsecureNoSandbox:     true,
				SandboxBinaryPath:     bwrapPath,
			})
		}, extraTests)
	})

	t.Run("Sandboxed", func(t *testing.T) {
		tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
			return NewProvisioner(Config{
				HostInfo: &protocol.HostInfo{
					ConsensusBackend:         cmt.BackendName,
					ConsensusProtocolVersion: version.Versions.ConsensusProtocol,
				},
				LoaderPath:            envRuntimeLoaderPath,
				RuntimeAttestInterval: 2 * time.Second,
				IAS:                   []api.Endpoint{ias},
				SandboxBinaryPath:     bwrapPath,
			})
		}, extraTests)
	})
}

func testAttestationWorker(t *testing.T, cfg host.Config, p host.Provisioner) {
	require := require.New(t)

	r, err := p.NewRuntime(cfg)
	require.NoError(err, "NewRuntime")
	r.Start()
	defer r.Stop()

	evCh, sub := r.WatchEvents()
	defer sub.Close()

	// Wait for a successful start event.
	select {
	case ev := <-evCh:
		require.NotNil(ev.Started, "should have received a successful start event")
		require.Equal(node.TEEHardwareIntelSGX, ev.Started.CapabilityTEE.Hardware, "TEE hardware should be Intel SGX")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive successful start event")
	}

	// Wait for a re-attestation (update) event.
	select {
	case ev := <-evCh:
		require.NotNil(ev.Updated, "should have received an update event")
		require.Equal(node.TEEHardwareIntelSGX, ev.Updated.CapabilityTEE.Hardware, "TEE hardware should be Intel SGX")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive update event")
	}
}
