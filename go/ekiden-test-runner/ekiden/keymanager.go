package ekiden

import (
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

const kmDescriptorFile = "keymanager_genesis.json"

// Keymanager is an ekiden keymanager.
type Keymanager struct {
	net *Network
	dir *env.Dir

	id           signature.PublicKey
	binary       string
	workerEntity *Entity
	teeHardware  node.TEEHardware

	consensusPort    uint16
	workerClientPort uint16
}

// KeymanagerCfg is the ekiden keymanager provisioning configuration.
type KeymanagerCfg struct {
	ID          signature.PublicKey
	Entity      *Entity
	TEEHardware node.TEEHardware
	Mrsigner    *sgx.Mrsigner

	WorkerEntity *Entity
	Binary       string
}

// LogPath returns the path to the node's log.
func (km *Keymanager) LogPath() string {
	return nodeLogPath(km.dir)
}

func (km *Keymanager) toGenesisArgs() []string {
	return []string{
		"--runtime", filepath.Join(km.dir.String(), kmDescriptorFile),
	}
}

func (km *Keymanager) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(km.consensusPort).
		workerClientPort(km.workerClientPort).
		workerKeymangerEnabled().
		workerKeymanagerRuntimeBinary(km.binary).
		workerKeymanagerRuntimeLoader(km.net.cfg.RuntimeLoaderBinary).
		workerKeymanagerRuntimeID(km.id).
		workerKeymanagerMayGenerate().
		appendNetwork(km.net).
		appendEntity(km.workerEntity)
	if km.teeHardware != node.TEEHardwareInvalid {
		args = args.workerKeymanagerTEEHardware(km.teeHardware)
	}

	if err := km.net.startEkidenNode(km.dir, nil, args, "keymanager"); err != nil {
		return errors.Wrap(err, "ekiden/keymanager: failed to launch node")
	}

	return nil
}

// NewKeymanger provisions a new keymanager and adds it to the network.
func (net *Network) NewKeymanager(cfg *KeymanagerCfg) (*Keymanager, error) {
	// XXX: Technically there can be more than one keymanager.
	if net.keymanager != nil {
		return nil, errors.New("ekiden/keymanager: already provisioned")
	}

	kmDir, err := net.baseDir.NewSubDir("keymanager")
	if err != nil {
		net.logger.Error("failed to create keymanager subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "ekiden/keymanager: failed to create keymanager subdir")
	}

	args := []string{
		"registry", "runtime", "init_genesis",
		"--datadir", kmDir.String(),
		"--runtime.id", cfg.ID.String(),
		"--runtime.kind", "keymanager",
		"--runtime.genesis.file", kmDescriptorFile,
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
	args = append(args, cfg.Entity.toGenesisArgs()...)

	w, err := kmDir.NewLogWriter("provision.log")
	if err != nil {
		return nil, err
	}
	defer w.Close()

	if err = net.runEkidenBinary(w, args...); err != nil {
		net.logger.Error("failed to provision keymanager",
			"err", err,
		)
		return nil, errors.Wrap(err, "ekiden/keymanager: failed to provision keymanager")
	}

	km := &Keymanager{
		net:              net,
		dir:              kmDir,
		id:               cfg.ID,
		binary:           cfg.Binary,
		workerEntity:     cfg.WorkerEntity,
		teeHardware:      cfg.TEEHardware,
		consensusPort:    net.nextNodePort,
		workerClientPort: net.nextNodePort + 1,
	}

	net.keymanager = km
	net.nextNodePort += 2

	return km, nil
}
