package oasis

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const rtDescriptorFile = "runtime_genesis.json"

// Runtime is an Oasis runtime.
type Runtime struct { // nolint: maligned
	dir *env.Dir

	id   signature.PublicKey
	kind registry.RuntimeKind

	binary      string
	teeHardware node.TEEHardware
	mrEnclave   *sgx.MrEnclave
	mrSigner    *sgx.MrSigner
}

// RuntimeCfg is the Oasis runtime provisioning configuration.
type RuntimeCfg struct { // nolint: maligned
	ID          signature.PublicKey
	Kind        registry.RuntimeKind
	Entity      *Entity
	Keymanager  *Runtime
	TEEHardware node.TEEHardware
	MrSigner    *sgx.MrSigner

	Binary       string
	GenesisState string

	ReplicaGroupSize       int
	ReplicaGroupBackupSize int
	StorageGroupSize       int
}

// ID returns the runtime ID.
func (rt *Runtime) ID() signature.PublicKey {
	return rt.id
}

func (rt *Runtime) toGenesisArgs() []string {
	return []string{
		"--runtime", filepath.Join(rt.dir.String(), rtDescriptorFile),
	}
}

// NewRuntime provisions a new runtime and adds it to the network.
func (net *Network) NewRuntime(cfg *RuntimeCfg) (*Runtime, error) {
	rtDir, err := net.baseDir.NewSubDir("runtime-" + cfg.ID.String())
	if err != nil {
		net.logger.Error("failed to create runtime subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "oasis/runtime: failed to create runtime subdir")
	}

	args := []string{
		"registry", "runtime", "init_genesis",
		"--datadir", rtDir.String(),
		"--runtime.id", cfg.ID.String(),
		"--runtime.kind", cfg.Kind.String(),
	}
	if cfg.Kind == registry.KindCompute {
		args = append(args, []string{
			"--runtime.replica_group_size", strconv.Itoa(cfg.ReplicaGroupSize),
			"--runtime.replica_group_backup_size", strconv.Itoa(cfg.ReplicaGroupBackupSize),
			"--runtime.storage_group_size", strconv.Itoa(cfg.StorageGroupSize),
		}...)

		if cfg.GenesisState != "" {
			args = append(args, "--runtime.genesis.state", cfg.GenesisState)
		}
	}
	var mrEnclave *sgx.MrEnclave
	if cfg.TEEHardware == node.TEEHardwareIntelSGX {
		if mrEnclave, err = deriveMrEnclave(cfg.Binary); err != nil {
			return nil, err
		}

		args = append(args, []string{
			"--runtime.tee_hardware", cfg.TEEHardware.String(),
			"--runtime.version.enclave", mrEnclave.String() + cfg.MrSigner.String(),
		}...)
	}
	if cfg.Keymanager != nil {
		args = append(args, []string{
			"--runtime.keymanager", cfg.Keymanager.id.String(),
		}...)
	}
	args = append(args, cfg.Entity.toGenesisArgs()...)

	w, err := rtDir.NewLogWriter("provision.log")
	if err != nil {
		return nil, err
	}
	defer w.Close()

	if err = net.runNodeBinary(w, args...); err != nil {
		net.logger.Error("failed to provision runtime",
			"err", err,
		)
		return nil, errors.Wrap(err, "oasis/runtime: failed to provision runtime")
	}

	rt := &Runtime{
		dir:         rtDir,
		id:          cfg.ID,
		kind:        cfg.Kind,
		binary:      cfg.Binary,
		teeHardware: cfg.TEEHardware,
		mrEnclave:   mrEnclave,
		mrSigner:    cfg.MrSigner,
	}
	net.runtimes = append(net.runtimes, rt)

	return rt, nil
}

func deriveMrEnclave(f string) (*sgx.MrEnclave, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, errors.Wrap(err, "oasis: failed to open enclave binary")
	}
	defer r.Close()

	var m sgx.MrEnclave
	if err = m.FromSgxs(r); err != nil {
		return nil, err
	}

	return &m, nil
}
