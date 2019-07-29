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
)

const rtDescriptorFile = "runtime_genesis.json"

// Runtime is an ekiden runtime.
type Runtime struct {
	dir *env.Dir

	id signature.PublicKey

	binary      string
	teeHardware node.TEEHardware
}

// RuntimeCfg is the ekiden runtime provisioning configuration.
type RuntimeCfg struct {
	ID          signature.PublicKey
	Entity      *Entity
	Keymanager  *Keymanager
	TEEHardware node.TEEHardware
	Mrsigner    *sgx.Mrsigner

	Binary string
	// XXX: Genesis

	ReplicaGroupSize       int
	ReplicaGroupBackupSize int
	StorageGroupSize       int
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
		"--runtime.kind", "compute",
		"--runtime.replica_group_size", strconv.Itoa(cfg.ReplicaGroupSize),
		"--runtime.replica_group_backup_size", strconv.Itoa(cfg.ReplicaGroupBackupSize),
		"--runtime.storage_group_size", strconv.Itoa(cfg.StorageGroupSize),
		// ${runtime_genesis:+--runtime.genesis.state ${runtime_genesis}}
	}
	if cfg.TEEHardware != node.TEEHardwareInvalid {
		var m *sgx.Mrenclave
		if m, err = deriveMrenclave(cfg.Binary); err != nil {
			return nil, err
		}

		args = append(args, []string{
			"--runtime.tee_hardware", cfg.TEEHardware.String(),
			"--runtime.version.enclave", cfg.Mrsigner.String() + m.String(),
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
		binary:      cfg.Binary,
		teeHardware: cfg.TEEHardware,
	}
	net.runtimes = append(net.runtimes, rt)

	return rt, nil
}

func deriveMrenclave(f string) (*sgx.Mrenclave, error) {
	r, err := os.Open(f)
	if err != nil {
		return nil, errors.Wrap(err, "ekiden: failed to open enclave binary")
	}
	defer r.Close()

	var m sgx.Mrenclave
	if err = m.FromSgxs(r); err != nil {
		return nil, err
	}

	return &m, nil
}
