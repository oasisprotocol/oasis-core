package remotesigner

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	remoteSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/remote"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	signerTests "github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/signer"
)

// Basic is the basic test case.
var Basic scenario.Scenario = newBasicImpl()

func newBasicImpl() *basicImpl {
	return &basicImpl{
		remoteSignerImpl: *newRemoteSignerImpl("basic"),
	}
}

type basicImpl struct {
	remoteSignerImpl
}

func (sc *basicImpl) Clone() scenario.Scenario {
	return &basicImpl{
		remoteSignerImpl: sc.remoteSignerImpl.Clone(),
	}
}

func (sc *basicImpl) Run(childEnv *env.Env) error {
	// Provision the server keys.
	sc.logger.Info("provisioning the server keys")
	serverBinary, _ := sc.flags.GetString(cfgServerBinary)
	if err := cli.RunSubCommand(
		childEnv,
		sc.logger,
		"init",
		serverBinary,
		[]string{
			"--" + cmdCommon.CfgDataDir, childEnv.Dir(),
			"init",
		},
	); err != nil {
		return err
	}
	serverCert, err := tls.LoadCertificate(filepath.Join(childEnv.Dir(), "remote_signer_server_cert.pem"))
	if err != nil {
		return err
	}

	// Since the server is backed by a file signer, load the keys so that
	// comparisons can be made.
	fsf, err := fileSigner.NewFactory(childEnv.Dir(), signature.SignerRoles...)
	if err != nil {
		return err
	}

	// Provision the client authentication certificates.
	sc.logger.Info("provisioning the client authentication certificates")
	if err = cli.RunSubCommand(
		childEnv,
		sc.logger,
		"init_client",
		serverBinary,
		[]string{
			"--" + cmdCommon.CfgDataDir, childEnv.Dir(),
			"init_client",
		},
	); err != nil {
		return err
	}

	// Start the server.
	sc.logger.Info("starting server")
	lw, err := childEnv.CurrentDir().NewLogWriter("server.log")
	if err != nil {
		return err
	}
	cmd, err := cli.StartSubCommand(
		childEnv,
		sc.logger,
		"server",
		serverBinary,
		[]string{
			"--" + cmdCommon.CfgDataDir, childEnv.Dir(),
			"--client.certificate", filepath.Join(childEnv.Dir(), "remote_signer_client_cert.pem"),
		},
		lw,
		lw,
	)
	if err != nil {
		return err
	}
	childEnv.AddTermOnCleanup(cmd)
	time.Sleep(2 * time.Second) // TODO: Is this needed?

	// Initialize a client.
	sc.logger.Info("initializing in-process client")
	clientCert, err := tls.Load(
		filepath.Join(childEnv.Dir(), "remote_signer_client_cert.pem"),
		filepath.Join(childEnv.Dir(), "remote_signer_client_key.pem"),
	)
	if err != nil {
		return err
	}
	sf, err := remoteSigner.NewFactory(
		&remoteSigner.FactoryConfig{
			Address:           "127.0.0.1:9001",
			ClientCertificate: clientCert,
			ServerCertificate: serverCert,
		},
		signature.SignerRoles...,
	)
	if err != nil {
		return err
	}

	// Run basic common signer tests.
	if err = signerTests.BasicTests(sf, sc.logger, signature.SignerRoles); err != nil {
		return err
	}

	// Remote specific verifcation.
	for _, v := range signature.SignerRoles {
		// Load()
		si, err := sf.Load(v)
		if err != nil {
			return fmt.Errorf("failed to Load(%v): %w", v, err)
		}

		// Ensure that the remote signer is reporting a matching public key.
		pk := si.Public()
		fsi, err := fsf.Load(v)
		if err != nil {
			return fmt.Errorf("failed to Load(%v) from file: %w", v, err)
		}
		if !pk.Equal(fsi.Public()) {
			return fmt.Errorf("public key mismatch: %v (expected: %v)", pk, fsi.Public())
		}
	}

	return nil
}
