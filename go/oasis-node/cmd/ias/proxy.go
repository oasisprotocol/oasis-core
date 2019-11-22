// Package ias implements the IAS sub commands.
package ias

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	tlsCert "github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/pprof"
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
	cfgWaitRuntimes  = "ias.wait_runtimes"

	tlsKeyFilename  = "ias_proxy.pem"
	tlsCertFilename = "ias_proxy_cert.pem"
)

var (
	proxyFlags = flag.NewFlagSet("", flag.ContinueOnError)

	iasCmd = &cobra.Command{
		Use:   "ias",
		Short: "IAS related utilities",
	}

	iasProxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "forward IAS requests under given client credentials",
		Run:   doProxy,
	}

	logger = logging.GetLogger("cmd/ias/proxy")
)

type proxyEnv struct {
	svcMgr  *background.ServiceManager
	grpcSrv *grpc.Server
}

// TLSCertPaths returns the TLS certificate and private key paths for
// the IAS proxy, based on the passed in data directory.
func TLSCertPaths(dataDir string) (string, string) {
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

	dataDir := cmdCommon.DataDir()
	if dataDir == "" {
		logger.Error("failed to query data directory")
		return
	}

	tlsCertPath, tlsKeyPath := TLSCertPaths(dataDir)
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
	env.grpcSrv, err = cmdGrpc.NewServerTCP(cert, false)
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
	grpcAuth, err := grpcAuthenticatorFromFlags(env.svcMgr.Ctx, cmd)
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
		if !flags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("ias: refusing to mock IAS responses")
		}
		cfg.DebugIsMock = true
	}

	return ias.NewIASEndpoint(cfg)
}

func grpcAuthenticatorFromFlags(ctx context.Context, cmd *cobra.Command) (ias.GRPCAuthenticator, error) {
	if viper.GetBool(cfgDebugSkipAuth) {
		if !flags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("ias: refusing to disable gRPC authentication")
		}
		logger.Warn("IAS gRPC authentication disabled, proxy is open")
		return nil, nil
	}
	if viper.GetBool(cfgUseGenesis) {
		return newGenesisAuthenticator()
	}

	return newRegistryAuthenticator(ctx, cmd)
}

// Register registers the ias sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	iasProxyCmd.Flags().AddFlagSet(proxyFlags)

	iasCmd.AddCommand(iasProxyCmd)
	parentCmd.AddCommand(iasCmd)
}

func init() {
	proxyFlags.String(cfgAuthCertFile, "", "the file with the client certificate")
	proxyFlags.String(cfgAuthKeyFile, "", "the file with the client private key")
	proxyFlags.String(cfgAuthCertCA, "", "the file with the CA that signed the client certificate")
	proxyFlags.String(cfgSPID, "", "SPID associated with the client certificate")
	proxyFlags.String(cfgQuoteSigType, "linkable", "quote signature type associated with the SPID")
	proxyFlags.Bool(cfgIsProduction, false, "use the production IAS endpoint")
	proxyFlags.Bool(cfgDebugMock, false, "generate mock IAS AVR responses (UNSAFE)")
	proxyFlags.Bool(cfgDebugSkipAuth, false, "disable proxy authentication (UNSAFE)")
	proxyFlags.Bool(cfgUseGenesis, false, "use a genesis document instead of the registry")
	proxyFlags.Int(cfgWaitRuntimes, 0, "wait for N runtimes to be registered before servicing requests")

	_ = proxyFlags.MarkHidden(cfgDebugMock)
	_ = proxyFlags.MarkHidden(cfgDebugSkipAuth)

	_ = viper.BindPFlags(proxyFlags)
	proxyFlags.AddFlagSet(metrics.Flags)
	proxyFlags.AddFlagSet(cmdGrpc.ServerTCPFlags)
	proxyFlags.AddFlagSet(cmdGrpc.ClientFlags)
	proxyFlags.AddFlagSet(flags.GenesisFileFlags)
	proxyFlags.AddFlagSet(flags.DebugDontBlameOasisFlag)
	proxyFlags.AddFlagSet(pprof.Flags)
}
