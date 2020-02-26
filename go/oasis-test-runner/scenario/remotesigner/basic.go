package remotesigner

import (
	"fmt"
	"path/filepath"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	remoteSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/remote"
	"github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/logging"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

const cfgRemoteSignerBinary = "remote_signer.binary"

var (
	// Basic is the basic test case.
	Basic scenario.Scenario = newBasicImpl()

	// Flags is the command line flags for the remote signer tests.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

func newBasicImpl() *basicImpl {
	return &basicImpl{
		logger: logging.GetLogger("remote-signer/basic"),
	}
}

type basicImpl struct {
	logger *logging.Logger
}

func (sc *basicImpl) Name() string {
	return "remote-signer/basic"
}

func (sc *basicImpl) Fixture() (*oasis.NetworkFixture, error) {
	return nil, nil
}

func (sc *basicImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	return nil
}

func (sc *basicImpl) Run(childEnv *env.Env) error {
	serverBinary := viper.GetString(cfgRemoteSignerBinary)

	// Provision the server keys.
	sc.logger.Info("provisioning the server keys")
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

	// EnsureRole()
	sc.logger.Info("testing EnsureRole")
	for _, v := range signature.SignerRoles {
		if err := sf.EnsureRole(v); err != nil {
			return fmt.Errorf("failed to EnsureRole(%v): %w", v, err)
		}
	}

	// Test each sub-key.
	for _, v := range signature.SignerRoles {
		// Load()
		si, err := sf.Load(v)
		if err != nil {
			return fmt.Errorf("failed to Load(%v): %w", v, err)
		}

		pk := si.Public()
		sc.logger.Info("remote signer loaded",
			"public_key", pk,
			"descr", si.String(),
		)

		// Ensure that the remote signer is reporting a matching public key.
		fsi, err := fsf.Load(v)
		if err != nil {
			return fmt.Errorf("failed to Load(%v) from file: %w", v, err)
		}
		if !pk.Equal(fsi.Public()) {
			return fmt.Errorf("public key mismatch: %v (expected: %v)", pk, fsi.Public())
		}

		msg := []byte("Alesia, alisanos, wake me when I'm gone")

		ctx := signature.NewContext(fmt.Sprintf("test context: %v", v))
		sig, err := si.ContextSign(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to Sign(%v): %w", v, err)
		}

		// Verify that the signature is sensible, no need to re-sign with
		// the file signer since the public key and context are sensible.
		if !pk.Verify(ctx, msg, sig) {
			return fmt.Errorf("failed to verify signature: %v", v)
		}
	}

	return nil
}

func init() {
	Flags.String(cfgRemoteSignerBinary, "oasis-remote-signer", "path to the remote-signer binary")
	_ = viper.BindPFlags(Flags)
}
