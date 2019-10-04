package ekiden

import (
	"fmt"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	workerCommon "github.com/oasislabs/ekiden/go/worker/common"
)

const (
	kmStatusFile = "keymanager_status.json"
	kmPolicyFile = "keymanager_policy.cbor"
)

// Keymanager is an ekiden keymanager.
type Keymanager struct { // nolint: maligned
	net *Network
	dir *env.Dir
	cmd *exec.Cmd

	runtime     *Runtime
	entity      *Entity
	restartable bool

	consensusPort    uint16
	workerClientPort uint16
}

// KeymanagerCfg is the ekiden keymanager provisioning configuration.
type KeymanagerCfg struct {
	Runtime *Runtime
	Entity  *Entity

	Restartable bool
}

// LogPath returns the path to the node's log.
func (km *Keymanager) LogPath() string {
	return nodeLogPath(km.dir)
}

// SocketPath returns the path to the node's gRPC socket.
func (km *Keymanager) SocketPath() string {
	return internalSocketPath(km.dir)
}

// IdentityKeyPath returns the paths to the node's identity key.
func (km *Keymanager) IdentityKeyPath() string {
	return nodeIdentityKeyPath(km.dir)
}

// P2PKeyPath returns the paths to the node's P2P key.
func (km *Keymanager) P2PKeyPath() string {
	return nodeP2PKeyPath(km.dir)
}

// TLSKeyPath returns the path to the node's TLS key.
func (km *Keymanager) TLSKeyPath() string {
	return nodeTLSKeyPath(km.dir)
}

// TLSCertPath returns the path to the node's TLS certificate.
func (km *Keymanager) TLSCertPath() string {
	return nodeTLSCertPath(km.dir)
}

// LocalStoragePath returns the path to the node's local storage.
func (km *Keymanager) LocalStoragePath() string {
	return filepath.Join(km.dir.String(), workerCommon.LocalStorageFile)
}

func (km *Keymanager) provisionGenesis() error {
	// Provision status and policy. We can only provision this here as we need
	// a list of runtimes allowed to query the key manager.
	statusArgs := []string{
		"keymanager", "init_status",
		"--debug.allow_test_keys",
		"--keymanager.status.id", km.runtime.id.String(),
		"--keymanager.status.file", filepath.Join(km.dir.String(), kmStatusFile),
	}
	if km.runtime.teeHardware == node.TEEHardwareInvalid {
		// Status without policy.
		statusArgs = append(statusArgs, "--keymanager.policy.file", "")
	} else {
		// Status and policy signed with test keys.
		kmPolicyPath := filepath.Join(km.dir.String(), kmPolicyFile)
		policyArgs := []string{
			"keymanager", "init_policy",
			"--keymanager.policy.file", kmPolicyPath,
			"--keymanager.policy.id", km.runtime.id.String(),
			"--keymanager.policy.serial", "1",
			"--keymanager.policy.enclave.id", km.runtime.mrsigner.String() + km.runtime.mrenclave.String(),
		}

		for _, rt := range km.net.runtimes {
			if rt.teeHardware == node.TEEHardwareInvalid || rt.kind != registry.KindCompute {
				continue
			}

			arg := fmt.Sprintf("%s=%s%s", rt.id, rt.mrsigner, rt.mrenclave)
			policyArgs = append(policyArgs, "--keymanager.policy.may.query", arg)
		}

		w, err := km.dir.NewLogWriter("provision-policy.log")
		if err != nil {
			return err
		}
		defer w.Close()

		if err = km.net.runEkidenBinary(w, policyArgs...); err != nil {
			km.net.logger.Error("failed to provision keymanager policy",
				"err", err,
			)
			return errors.Wrap(err, "ekiden/keymanager: failed to provision keymanager policy")
		}

		// Sign policy with test keys.
		signArgsTpl := []string{
			"keymanager", "sign_policy",
			"--debug.allow_test_keys",
			"--keymanager.policy.file", kmPolicyPath,
		}
		for i := 1; i <= 3; i++ {
			signatureFile := filepath.Join(km.dir.String(), fmt.Sprintf("%s.sign.%d", kmPolicyFile, i))
			signArgs := append([]string{}, signArgsTpl...)
			signArgs = append(signArgs, []string{
				"--keymanager.policy.signature.file", signatureFile,
				"--keymanager.policy.testkey", fmt.Sprintf("%d", i),
			}...)
			statusArgs = append(statusArgs, "--keymanager.policy.signature.file", signatureFile)

			w, err := km.dir.NewLogWriter("provision-policy-sign.log")
			if err != nil {
				return err
			}
			defer w.Close()

			if err = km.net.runEkidenBinary(w, signArgs...); err != nil {
				km.net.logger.Error("failed to sign keymanager policy",
					"err", err,
				)
				return errors.Wrap(err, "ekiden/keymanager: failed to sign keymanager policy")
			}
		}

		statusArgs = append(statusArgs, "--keymanager.policy.file", kmPolicyPath)
	}

	w, err := km.dir.NewLogWriter("provision-status.log")
	if err != nil {
		return err
	}
	defer w.Close()

	if err = km.net.runEkidenBinary(w, statusArgs...); err != nil {
		km.net.logger.Error("failed to provision keymanager status",
			"err", err,
		)
		return errors.Wrap(err, "ekiden/keymanager: failed to provision keymanager status")
	}

	return nil
}

func (km *Keymanager) toGenesisArgs() []string {
	return []string{
		"--keymanager", filepath.Join(km.dir.String(), kmStatusFile),
		"--keymanager.operator", filepath.Join(km.entity.dir.String(), "entity_genesis.json"),
	}
}

func (km *Keymanager) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(km.consensusPort).
		workerClientPort(km.workerClientPort).
		workerKeymangerEnabled().
		workerKeymanagerRuntimeBinary(km.runtime.binary).
		workerKeymanagerRuntimeLoader(km.net.cfg.RuntimeLoaderBinary).
		workerKeymanagerRuntimeID(km.runtime.id).
		workerKeymanagerMayGenerate().
		appendNetwork(km.net).
		appendEntity(km.entity)
	if km.runtime.teeHardware != node.TEEHardwareInvalid {
		args = args.workerKeymanagerTEEHardware(km.runtime.teeHardware)
	}

	var err error
	if km.cmd, err = km.net.startEkidenNode(km.dir, nil, args, "keymanager", false, km.restartable); err != nil {
		return errors.Wrap(err, "ekiden/keymanager: failed to launch node")
	}

	return nil
}

func (km *Keymanager) stopNode() error {
	if km.cmd == nil {
		return nil
	}

	// Stop the node and wait for it to stop.
	_ = km.cmd.Process.Kill()
	_ = km.cmd.Wait()
	km.cmd = nil
	return nil
}

// Restart kills the key manager node, waits for it to stop, and starts it again.
func (km *Keymanager) Restart() error {
	if err := km.stopNode(); err != nil {
		return err
	}
	return km.startNode()
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

	km := &Keymanager{
		net:              net,
		dir:              kmDir,
		runtime:          cfg.Runtime,
		entity:           cfg.Entity,
		restartable:      cfg.Restartable,
		consensusPort:    net.nextNodePort,
		workerClientPort: net.nextNodePort + 1,
	}

	net.keymanager = km
	net.nextNodePort += 2

	return km, nil
}
