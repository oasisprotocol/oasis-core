package ekiden

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

const rtDescriptorFile = "runtime_genesis.json"

// Runtime is an ekiden runtime.
type Runtime struct { // nolint: maligned
	dir *env.Dir

	id   signature.PublicKey
	kind registry.RuntimeKind

	binary      string
	teeHardware node.TEEHardware
	mrenclave   *sgx.MrEnclave
	mrsigner    *sgx.MrSigner
}

// RuntimeCfg is the ekiden runtime provisioning configuration.
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
		return nil, errors.Wrap(err, "ekiden/runtime: failed to create runtime subdir")
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
	var mrenclave *sgx.MrEnclave
	if cfg.TEEHardware == node.TEEHardwareIntelSGX {
		if mrenclave, err = deriveMrenclave(cfg.Binary); err != nil {
			return nil, err
		}

		args = append(args, []string{
			"--runtime.tee_hardware", cfg.TEEHardware.String(),
			"--runtime.version.enclave", mrenclave.String() + cfg.MrSigner.String(),
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

	if err = net.runEkidenBinary(w, args...); err != nil {
		net.logger.Error("failed to provision runtime",
			"err", err,
		)
		return nil, errors.Wrap(err, "ekiden/runtime: failed to provision runtime")
	}

	rt := &Runtime{
		dir:         rtDir,
		id:          cfg.ID,
		kind:        cfg.Kind,
		binary:      cfg.Binary,
		teeHardware: cfg.TEEHardware,
		mrenclave:   mrenclave,
		mrsigner:    cfg.MrSigner,
	}
	net.runtimes = append(net.runtimes, rt)

	return rt, nil
}

func deriveMrenclave(f string) (*sgx.MrEnclave, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, errors.Wrap(err, "ekiden: failed to open enclave binary")
	}
	defer r.Close()

	var m sgx.MrEnclave
	if err = m.FromSgxs(r); err != nil {
		return nil, err
	}

	return &m, nil
}
