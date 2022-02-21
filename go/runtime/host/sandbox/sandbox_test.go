package sandbox

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	tendermint "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/tests"
)

var envRuntimePath = os.Getenv("OASIS_TEST_RUNTIME_HOST_BUNDLE_PATH")

func TestProvisionerSandbox(t *testing.T) {
	const bwrapPath = "/usr/bin/bwrap" // Sensible systems only.

	// Skip test if there is no runtime configured.
	if envRuntimePath == "" {
		t.Skip("skipping as OASIS_TEST_RUNTIME_HOST_BUNDLE_PATH is not set")
	}

	bnd, err := bundle.Open(envRuntimePath)
	require.NoError(t, err, "bundle.Open")

	cfg := host.Config{
		Bundle: &host.RuntimeBundle{
			Bundle: bnd,
			Path:   envRuntimePath,
		},
	}

	t.Run("Naked", func(t *testing.T) {
		tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
			return New(Config{
				HostInfo: &protocol.HostInfo{
					ConsensusBackend:         tendermint.BackendName,
					ConsensusProtocolVersion: version.Versions.ConsensusProtocol,
				},
				InsecureNoSandbox: true,
				SandboxBinaryPath: bwrapPath,
			})
		}, nil)
	})

	t.Run("Sandboxed", func(t *testing.T) {
		tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
			return New(Config{
				HostInfo: &protocol.HostInfo{
					ConsensusBackend:         tendermint.BackendName,
					ConsensusProtocolVersion: version.Versions.ConsensusProtocol,
				},
				SandboxBinaryPath: bwrapPath,
			})
		}, nil)
	})
}
