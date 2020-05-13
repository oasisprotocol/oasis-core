package sandbox

import (
	"os"
	"testing"

	"github.com/oasislabs/oasis-core/go/runtime/host"
	"github.com/oasislabs/oasis-core/go/runtime/host/tests"
)

var envRuntimePath = os.Getenv("OASIS_TEST_RUNTIME_HOST_RUNTIME_PATH")

func TestProvisionerSandbox(t *testing.T) {
	// Skip test if there is no runtime configured.
	if envRuntimePath == "" {
		t.Skip("skipping as OASIS_TEST_RUNTIME_HOST_RUNTIME_PATH is not set")
	}

	cfg := host.Config{
		Path: envRuntimePath,
	}

	t.Run("Naked", func(t *testing.T) {
		tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
			return New(Config{
				InsecureNoSandbox: true,
			})
		}, nil)
	})

	t.Run("Sandboxed", func(t *testing.T) {
		tests.TestProvisioner(t, cfg, func() (host.Provisioner, error) {
			return New(Config{})
		}, nil)
	})
}
