// Package ias implements the IAS sub commands.
package ias

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tlsCert "github.com/oasislabs/ekiden/go/common/crypto/tls"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/metrics"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/pprof"
)

const (
	cfgAuthCertFile  = "ias.auth.cert"
	cfgAuthKeyFile   = "ias.auth.cert.key"
	cfgAuthCertCA    = "ias.auth.cert.ca"
	cfgIsProduction  = "ias.production"
	cfgSPID          = "ias.spid"
	cfgQuoteSigType  = "ias.quote.signature_type"
	cfgDebugMock     = "ias.debug.mock"
	cfgDebugSkipAuth = "ias.debug.skip_auth"
	cfgUseGenesis    = "ias.use_genesis"

	tlsKeyFilename  = "ias_proxy.pem"
	tlsCertFilename = "ias_proxy_cert.pem"
)

var (
	iasCmd = &cobra.Command{
		Use:   "ias",
		Short: "IAS related utilities",
	}

	iasProxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "forward IAS requests under given client credentials",
		Run:   doProxy,
		PreRun: func(cmd *cobra.Command, args []string) {
			RegisterFlags(cmd)
		},
	}

	logger = logging.GetLogger("cmd/ias/proxy")
)

type proxyEnv struct {
	svcMgr  *background.ServiceManager
	grpcSrv *grpc.Server
}

func tlsCertPaths(dataDir string) (string, string) {
	var (
		certPath = filepath.Join(dataDir, tlsCertFilename)
		keyPath  = filepath.Join(dataDir, tlsKeyFilename)
	)

	return certPath, keyPath
}

func doProxy(cmd *cobra.Command, args []string) {
	var startOk bool
	defer func() {
		if !startOk {
			os.Exit(1)
		}
	}()

	env := &proxyEnv{
		svcMgr: background.NewServiceManager(logger),
	}
	defer func() { env.svcMgr.Cleanup() }()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	dataDir, err := cmdCommon.DataDirOrPwd()
	if err != nil {
		logger.Error("failed to query data directory",
			"err", err,
		)
		return
	}

	tlsCertPath, tlsKeyPath := tlsCertPaths(dataDir)
	cert, err := tlsCert.LoadOrGenerate(tlsCertPath, tlsKeyPath, ias.CommonName)
	if err != nil {
		logger.Error("failed to load or generate TLS cert",
			"err", err,
		)
		return
	}

	endpoint, err := iasEndpointFromFlags()
	if err != nil {
		logger.Error("failed to initialize IAS endpoint",
			"err", err,
		)
		return
	}

	// Initialize the gRPC server.
	env.grpcSrv, err = cmdGrpc.NewServerTCP(cert)
	if err != nil {
		logger.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metrics, err := metrics.New(env.svcMgr.Ctx)
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := pprof.New(env.svcMgr.Ctx)
	if err != nil {
		logger.Error("failed to initialize pprof server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		logger.Error("failed to start pprof server",
			"err", err,
		)
		return
	}

	// Initialize the IAS proxy authenticator.
	grpcAuth, err := grpcAuthenticatorFromFlags()
	if err != nil {
		logger.Error("failed to initialize IAS gRPC authentiator",
			"err", err,
		)
		return
	}

	// Initialize the IAS proxy.
	ias.NewGRPCServer(env.grpcSrv.Server(), endpoint, grpcAuth)

	// Start metric server.
	if err = metrics.Start(); err != nil {
		logger.Error("failed to start metric server",
			"err", err,
		)
		return
	}

	// Start the gRPC server.
	if err = env.grpcSrv.Start(); err != nil {
		logger.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	startOk = true
	logger.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	env.svcMgr.Wait()
}

func iasEndpointFromFlags() (ias.Endpoint, error) {
	cfg := &ias.EndpointConfig{
		SPID: viper.GetString(cfgSPID),
	}

	quoteSigType := viper.GetString(cfgQuoteSigType)
	switch strings.ToLower(quoteSigType) {
	case "unlinkable":
		cfg.QuoteSignatureType = ias.SignatureUnlinkable
	case "linkable":
		cfg.QuoteSignatureType = ias.SignatureLinkable
	default:
		return nil, fmt.Errorf("ias: invalid signature type: %s", quoteSigType)
	}

	if !viper.GetBool(cfgDebugMock) {
		if authCertCA := viper.GetString(cfgAuthCertCA); authCertCA != "" {
			certData, err := ioutil.ReadFile(authCertCA)
			if err != nil {
				return nil, err
			}

			cfg.AuthCertCA, _, err = ias.CertFromPEM(certData)
			if err != nil {
				return nil, err
			}
		}

		authCert, err := tls.LoadX509KeyPair(viper.GetString(cfgAuthCertFile), viper.GetString(cfgAuthKeyFile))
		if err != nil {
			return nil, fmt.Errorf("ias: failed to load client certificate: %s", err)
		}
		authCert.Leaf, err = x509.ParseCertificate(authCert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("ias: failed to parse client leaf certificate: %s", err)
		}
		cfg.AuthCert = &authCert

		cfg.IsProduction = viper.GetBool(cfgIsProduction)
	} else {
		cfg.DebugIsMock = true
	}

	return ias.NewIASEndpoint(cfg)
}

func grpcAuthenticatorFromFlags() (ias.GRPCAuthenticator, error) {
	if viper.GetBool(cfgDebugSkipAuth) {
		logger.Warn("IAS gRPC authentication disabled, proxy is open")
		return nil, nil
	}
	if viper.GetBool(cfgUseGenesis) {
		return newGenesisAuthenticator()
	}

	return nil, fmt.Errorf("ias: no authentication configured")
}

// RegisterFlags registers the flags used by the proxy command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgAuthCertFile, "", "the file with the client certificate")
		cmd.Flags().String(cfgAuthKeyFile, "", "the file with the client private key")
		cmd.Flags().String(cfgAuthCertCA, "", "the file with the CA that signed the client certificate")
		cmd.Flags().String(cfgSPID, "", "SPID associated with the client certificate")
		cmd.Flags().String(cfgQuoteSigType, "linkable", "quote signature type associated with the SPID")
		cmd.Flags().Bool(cfgIsProduction, false, "use the production IAS endpoint")
		cmd.Flags().Bool(cfgDebugMock, false, "generate mock IAS AVR responses (UNSAFE)")
		cmd.Flags().Bool(cfgDebugSkipAuth, false, "disable proxy authentication (UNSAFE)")
		cmd.Flags().Bool(cfgUseGenesis, false, "use a genesis document instead of the registry")
	}

	for _, v := range []string{
		cfgAuthCertFile,
		cfgAuthKeyFile,
		cfgAuthCertCA,
		cfgSPID,
		cfgQuoteSigType,
		cfgIsProduction,
		cfgDebugMock,
		cfgDebugSkipAuth,
		cfgUseGenesis,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}

	for _, v := range []func(*cobra.Command){
		metrics.RegisterFlags,
		cmdGrpc.RegisterServerTCPFlags,
		flags.RegisterGenesisFile,
		pprof.RegisterFlags,
	} {
		v(cmd)
	}
}

// Register registers the ias sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	RegisterFlags(iasProxyCmd)

	iasCmd.AddCommand(iasProxyCmd)
	parentCmd.AddCommand(iasCmd)
}
