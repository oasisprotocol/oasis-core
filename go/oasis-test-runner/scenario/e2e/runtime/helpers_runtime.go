package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/rust"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common/api"
)

var (
	// KeyValueRuntimeBinary is the name of the simple key/value runtime binary.
	KeyValueRuntimeBinary = "simple-keyvalue"
	// KeyValueRuntimeUpgradeBinary is the name of the upgraded simple key/value runtime binary.
	KeyValueRuntimeUpgradeBinary = "simple-keyvalue-upgrade"
	// KeyManagerRuntimeBinary is the name of the simple key manager runtime binary.
	KeyManagerRuntimeBinary = "simple-keymanager"
	// KeyManagerRuntimeUpgradeBinary is the name of the upgraded simple key manager runtime binary.
	KeyManagerRuntimeUpgradeBinary = "simple-keymanager-upgrade"

	// KeyValueRuntimeID is the ID of the simple key/value runtime.
	KeyValueRuntimeID common.Namespace
	// KeyManagerRuntimeID is the ID of the key manager runtime.
	KeyManagerRuntimeID common.Namespace

	_ = KeyManagerRuntimeID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
	_ = KeyValueRuntimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
)

// ResolveRuntimeBinaries returns the paths to the runtime binaries.
func (sc *Scenario) ResolveRuntimeBinaries(baseRuntimeBinary string) map[node.TEEHardware]string {
	binaries := make(map[node.TEEHardware]string)
	for _, tee := range []node.TEEHardware{
		node.TEEHardwareInvalid,
		node.TEEHardwareIntelSGX,
	} {
		binaries[tee] = sc.ResolveRuntimeBinary(baseRuntimeBinary, tee)
	}
	return binaries
}

// ResolveRuntimeBinary returns the path to the runtime binary.
func (sc *Scenario) ResolveRuntimeBinary(runtimeBinary string, tee node.TEEHardware) string {
	var runtimeExt, path string
	switch tee {
	case node.TEEHardwareInvalid:
		runtimeExt = ""
		path, _ = sc.Flags.GetString(cfgRuntimeBinaryDirDefault)
	case node.TEEHardwareIntelSGX:
		runtimeExt = ".sgxs"
		path, _ = sc.Flags.GetString(cfgRuntimeBinaryDirIntelSGX)
	}

	return filepath.Join(path, runtimeBinary+runtimeExt)
}

// BuildRuntimes builds the specified runtime binaries using the provided trust root, if given.
func (sc *Scenario) BuildRuntimes(ctx context.Context, childEnv *env.Env, runtimes map[common.Namespace]string, trustRoot *e2e.TrustRoot) error {
	// Determine the required directories for building the runtime with an embedded trust root.
	buildDir, targetDir, err := sc.BuildTargetDirs()
	if err != nil {
		return err
	}

	// Determine TEE hardware.
	teeHardware, err := sc.TEEHardware()
	if err != nil {
		return err
	}

	// Prepare the builder.
	builder := rust.NewBuilder(childEnv, buildDir, targetDir, teeHardware)

	// Build runtimes one by one.
	var errs *multierror.Error
	for runtimeID, runtimeBinary := range runtimes {
		switch trustRoot {
		case nil:
			sc.Logger.Info("building runtime without embedded trust root",
				"runtime_id", runtimeID,
				"runtime_binary", runtimeBinary,
			)
		default:
			sc.Logger.Info("building runtime with embedded trust root",
				"runtime_id", runtimeID,
				"runtime_binary", runtimeBinary,
				"trust_root_height", trustRoot.Height,
				"trust_root_hash", trustRoot.Hash,
				"trust_root_chain_context", trustRoot.ChainContext,
			)

			// Prepare environment.
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_HEIGHT", trustRoot.Height)
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_HASH", trustRoot.Hash)
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_CHAIN_CONTEXT", trustRoot.ChainContext)
			builder.SetEnv("OASIS_TESTS_CONSENSUS_TRUST_RUNTIME_ID", runtimeID.String())
		}

		// Build a new runtime with the given trust root embedded.
		if err = builder.Build(runtimeBinary); err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	if err = errs.ErrorOrNil(); err != nil {
		return fmt.Errorf("failed to build runtimes: %w", err)
	}

	return nil
}

// BuildAllRuntimes builds all runtime binaries, i.e. the key/value and the key manager runtime.
func (sc *Scenario) BuildAllRuntimes(ctx context.Context, childEnv *env.Env, trustRoot *e2e.TrustRoot) error {
	runtimes := map[common.Namespace]string{
		KeyValueRuntimeID:   KeyValueRuntimeBinary,
		KeyManagerRuntimeID: KeyManagerRuntimeBinary,
	}

	return sc.BuildRuntimes(ctx, childEnv, runtimes, trustRoot)
}

// EnsureActiveVersion ensures that all compute workers have the correct active version
// of the given runtime.
func (sc *Scenario) EnsureActiveVersion(ctx context.Context, rt *oasis.Runtime, v version.Version) error {
	ctx, cancel := context.WithTimeout(ctx, versionActivationTimeout)
	defer cancel()

	sc.Logger.Info("ensuring that all compute workers have the correct active version",
		"version", v,
	)

	for _, node := range sc.Net.ComputeWorkers() {
		nodeCtrl, err := oasis.NewController(node.SocketPath())
		if err != nil {
			return fmt.Errorf("%s: failed to create controller: %w", node.Name, err)
		}

		// Wait for the version to become active and ensure no suspension observed.
		for {
			status, err := nodeCtrl.GetStatus(ctx)
			if err != nil {
				return fmt.Errorf("%s: failed to query status: %w", node.Name, err)
			}

			provisioner := status.Runtimes[rt.ID()].Provisioner
			if provisioner != "sandbox" && provisioner != "sgx" {
				return fmt.Errorf("%s: unexpected runtime provisioner for runtime '%s': %s", node.Name, rt.ID(), provisioner)
			}

			cs := status.Runtimes[rt.ID()].Committee
			if cs == nil {
				return fmt.Errorf("%s: missing status for runtime '%s'", node.Name, rt.ID())
			}

			if cs.ActiveVersion == nil {
				return fmt.Errorf("%s: no version is active", node.Name)
			}
			// Retry if not yet activated.
			if cs.ActiveVersion.ToU64() < v.ToU64() {
				time.Sleep(1 * time.Second)
				continue
			}
			if *cs.ActiveVersion != v {
				return fmt.Errorf("%s: unexpected active version (expected: %s got: %s)", node.Name, v, cs.ActiveVersion)
			}
			if cs.Status != commonWorker.StatusStateReady {
				return fmt.Errorf("%s: runtime is not ready (got: %s)", node.Name, cs.Status)
			}
			break
		}
	}
	return nil
}
