// Package cmd implements the commands for the oasis-remote-signer executable.
package cmd

import (
	"crypto/rand"
	goTls "crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/remote"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/grpc/auth"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdBackground "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
)

const (
	cfgClientCertificate = "client.certificate"

	// clientCommonName is the common name on the client TLS certificates.
	clientCommonName = "remote-signer-client"
)

var (
	rootCmd = &cobra.Command{
		Use:     "oasis-remote-signer",
		Short:   "Oasis Remote Signer",
		Version: version.SoftwareVersion,
		RunE:    runRoot,
	}

	initServerCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize server keys",
		Run:   doServerInit,
	}

	initClientCmd = &cobra.Command{
		Use:   "init_client",
		Short: "initialize client certificate",
		Run:   doClientInit,
	}

	rootFlags = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("remote-signer")
)

// Execute spawns the main entry point after handling the config file.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func ensureDataDir() (string, error) {
	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		return "", fmt.Errorf("remote-signer: datadir is mandatory")
	}

	return dataDir, nil
}

func doServerInit(cmd *cobra.Command, args []string) {
	if _, _, err := serverInit(true); err != nil {
		logger.Error("failed to initialize server keys",
			"err", err,
		)
		os.Exit(1)
	}
}

func serverInit(provisionKeys bool) (signature.SignerFactory, *goTls.Certificate, error) {
	dataDir, err := ensureDataDir()
	if err != nil {
		return nil, nil, err
	}

	sf, err := cmdSigner.NewFactory(cmdSigner.Backend(), dataDir, signature.SignerRoles...)
	if err != nil {
		logger.Error("failed to create signer factory",
			"err", err,
		)
		return nil, nil, fmt.Errorf("remote-signer: failed to create signer: %w", err)
	}
	for _, v := range signature.SignerRoles {
		switch provisionKeys {
		case true:
			if _, err = sf.Generate(v, rand.Reader); err != nil {
				return nil, nil, fmt.Errorf("remote-signer: failed to provision key (%v): %w", v, err)
			}
		case false:
			if _, err = sf.Load(v); err != nil {
				return nil, nil, fmt.Errorf("remote-signer: failed to load key (%v): %w", v, err)
			}
		}
	}

	// Load the server certificate, provisioning if required.
	cert, err := tls.LoadOrGenerate(
		filepath.Join(dataDir, "remote_signer_server_cert.pem"),
		filepath.Join(dataDir, "remote_signer_server_key.pem"),
		"remote-signer-server",
	)
	if err != nil {
		logger.Error("failed to load/generate grpc TLS cert",
			"err", err,
		)
		return nil, nil, fmt.Errorf("remote-signer: failed to load/generate gRPC TLS certificate: %w", err)
	}

	return sf, cert, nil
}

func doClientInit(cmd *cobra.Command, args []string) {
	if err := func() error {
		dataDir, err := ensureDataDir()
		if err != nil {
			return err
		}

		_, err = tls.LoadOrGenerate(
			filepath.Join(dataDir, "remote_signer_client_cert.pem"),
			filepath.Join(dataDir, "remote_signer_client_key.pem"),
			clientCommonName,
		)
		return err
	}(); err != nil {
		logger.Error("failed to initialize client keys",
			"err", err,
		)
		os.Exit(1)
	}
}

func runRoot(cmd *cobra.Command, args []string) error {
	// Initialize all of the server keys.
	sf, cert, err := serverInit(false)
	if err != nil {
		logger.Error("failed to initialize server keys",
			"err", err,
		)
		return err
	}

	// Load the client certificate to be granted access.
	clientCertPath := viper.GetString(cfgClientCertificate)
	tlsCert, err := tls.LoadCertificate(clientCertPath)
	if err != nil {
		logger.Error("failed to load client TLS certificate",
			"err", err,
		)
		return err
	}
	clientCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		logger.Error("failed to parse client TLS certificate",
			"err", err,
		)
	}
	peerCertAuth := auth.NewPeerCertAuthenticator()
	peerCertAuth.AllowPeerCertificate(clientCert)

	// Initialize the gRPC server.
	svrCfg := &grpc.ServerConfig{
		Name:             "remote-signer",
		Port:             uint16(viper.GetInt(cmdGrpc.CfgServerPort)),
		Identity:         &identity.Identity{},
		AuthFunc:         peerCertAuth.AuthFunc,
		ClientCommonName: clientCommonName,
	}
	svrCfg.Identity.SetTLSCertificate(cert)
	svr, err := grpc.NewServer(svrCfg)
	if err != nil {
		logger.Error("failed to instantiate gRPC server",
			"err", err,
		)
		return err
	}
	signature.UnsafeAllowUnregisteredContexts()
	remote.RegisterService(svr.Server(), sf)

	// Run the gRPC server.
	if err = svr.Start(); err != nil {
		logger.Error("failed to start gRPC server",
			"err", err,
		)
		return err
	}

	// Wait for graceful termination.
	sm := cmdBackground.NewServiceManager(logger)
	sm.Register(svr)
	defer sm.Cleanup()
	sm.Wait()

	return nil
}

func init() {
	cmdCommon.SetBasicVersionTemplate(rootCmd)

	_ = viper.BindPFlags(cmdCommon.RootFlags)

	rootFlags.String(cfgClientCertificate, "client_cert.pem", "client TLS certificate (REQUIRED)")
	_ = viper.BindPFlags(rootFlags)

	rootCmd.PersistentFlags().AddFlagSet(cmdCommon.RootFlags)
	rootCmd.Flags().AddFlagSet(cmdGrpc.ServerTCPFlags)
	rootCmd.Flags().AddFlagSet(cmdSigner.Flags)
	rootCmd.Flags().AddFlagSet(rootFlags)

	rootCmd.AddCommand(initServerCmd)
	rootCmd.AddCommand(initClientCmd)

	cobra.OnInitialize(func() {
		if err := cmdCommon.Init(); err != nil {
			cmdCommon.EarlyLogAndExit(err)
		}
	})
}
