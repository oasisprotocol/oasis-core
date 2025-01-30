package sandbox

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	cmt "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
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

	tmpDir := t.TempDir()
	err = bnd.WriteExploded(tmpDir)
	require.NoError(t, err, "bnd.WriteExploded")

	cfg := host.Config{
		Name: bnd.Manifest.Name,
		ID:   bnd.Manifest.ID,
	}

	for _, comp := range bnd.Manifest.Components {
		cfg.Component = &bundle.ExplodedComponent{
			Component:       comp,
			ExplodedDataDir: tmpDir,
		}

		t.Run(fmt.Sprintf("Naked %s", comp.ID()), func(t *testing.T) {
			tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
				return NewProvisioner(Config{
					HostInfo: &protocol.HostInfo{
						ConsensusBackend:         cmt.BackendName,
						ConsensusProtocolVersion: version.Versions.ConsensusProtocol,
					},
					InsecureNoSandbox: true,
					SandboxBinaryPath: bwrapPath,
				})
			}, nil)
		})

		t.Run(fmt.Sprintf("Sandboxed %s", comp.ID()), func(t *testing.T) {
			tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
				return NewProvisioner(Config{
					HostInfo: &protocol.HostInfo{
						ConsensusBackend:         cmt.BackendName,
						ConsensusProtocolVersion: version.Versions.ConsensusProtocol,
					},
					SandboxBinaryPath: bwrapPath,
				})
			}, nil)
		})
	}
}
