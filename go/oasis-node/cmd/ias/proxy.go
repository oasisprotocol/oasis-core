// Package ias implements the IAS sub commands.
package ias

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	tlsCert "github.com/oasisprotocol/oasis-core/go/common/crypto/tls"
	"github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	cmnIAS "github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	ias "github.com/oasisprotocol/oasis-core/go/ias/api"
	iasHTTP "github.com/oasisprotocol/oasis-core/go/ias/http"
	iasProxy "github.com/oasisprotocol/oasis-core/go/ias/proxy"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/background"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/pprof"
)

const (
	envAuthAPIKey    = "OASIS_IAS_APIKEY" //nolint:gosec
	cfgAuthAPIKey    = "ias.auth.api_key" //nolint:gosec
	cfgIsProduction  = "ias.production"
	envSPID          = "OASIS_IAS_SPID"
	cfgSPID          = "ias.spid"
	cfgQuoteSigType  = "ias.quote.signature_type"
	cfgDebugMock     = "ias.debug.mock"
	cfgDebugSkipAuth = "ias.debug.skip_auth"
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
	cert, err := tlsCert.LoadOrGenerate(tlsCertPath, tlsKeyPath, iasProxy.CommonName)
	if err != nil {
		logger.Error("failed to load or generate TLS cert",
			"err", err,
		)
		return
	}

	logger.Info("loaded/generated IAS TLS certificate",
		"public_key", cert.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey),
	)

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
	authenticator, err := grpcAuthenticatorFromFlags(env.svcMgr.Ctx, cmd)
	if err != nil {
		logger.Error("failed to initialize IAS gRPC authenticator",
			"err", err,
		)
		return
	}

	// Initialize the IAS proxy.
	proxy := iasProxy.New(endpoint, authenticator)
	ias.RegisterService(env.grpcSrv.Server(), proxy)

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
	cfg := &iasHTTP.Config{
		SPID: viper.GetString(cfgSPID),
	}

	quoteSigType := viper.GetString(cfgQuoteSigType)
	switch strings.ToLower(quoteSigType) {
	case "unlinkable":
		cfg.QuoteSignatureType = cmnIAS.SignatureUnlinkable
	case "linkable":
		cfg.QuoteSignatureType = cmnIAS.SignatureLinkable
	default:
		return nil, fmt.Errorf("ias: invalid signature type: %s", quoteSigType)
	}

	if viper.GetBool(cfgDebugMock) {
		if !flags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("ias: refusing to mock IAS responses")
		}
		cfg.DebugIsMock = true
	} else {
		apiKey := viper.GetString(cfgAuthAPIKey)
		if apiKey == "" {
			return nil, fmt.Errorf("ias: missing IAS Client API key")
		}
		cfg.SubscriptionKey = apiKey
		cfg.IsProduction = viper.GetBool(cfgIsProduction)
	}

	return iasHTTP.New(cfg)
}

func grpcAuthenticatorFromFlags(ctx context.Context, cmd *cobra.Command) (iasProxy.Authenticator, error) {
	if viper.GetBool(cfgDebugSkipAuth) {
		if !flags.DebugDontBlameOasis() {
			return nil, fmt.Errorf("ias: refusing to disable gRPC authentication")
		}
		logger.Warn("IAS gRPC authentication disabled, proxy is open")
		return nil, nil
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
	proxyFlags.String(cfgAuthAPIKey, "", "the IAS subscription API key")
	proxyFlags.String(cfgSPID, "", "SPID associated with the client certificate")
	proxyFlags.String(cfgQuoteSigType, "linkable", "quote signature type associated with the SPID")
	proxyFlags.Bool(cfgIsProduction, false, "use the production IAS endpoint")
	proxyFlags.Bool(cfgDebugMock, false, "generate mock IAS AVR responses (UNSAFE)")
	proxyFlags.Bool(cfgDebugSkipAuth, false, "disable proxy authentication (UNSAFE)")
	proxyFlags.Int(cfgWaitRuntimes, 0, "wait for N runtimes to be registered before servicing requests")

	_ = proxyFlags.MarkHidden(cfgDebugMock)
	_ = proxyFlags.MarkHidden(cfgDebugSkipAuth)

	_ = viper.BindEnv(cfgAuthAPIKey, envAuthAPIKey)
	_ = viper.BindEnv(cfgSPID, envSPID)

	_ = viper.BindPFlags(proxyFlags)
	proxyFlags.AddFlagSet(metrics.Flags)
	proxyFlags.AddFlagSet(cmdGrpc.ServerLocalFlags)
	proxyFlags.AddFlagSet(cmdGrpc.ServerTCPFlags)
	proxyFlags.AddFlagSet(cmdGrpc.ClientFlags)
	proxyFlags.AddFlagSet(flags.GenesisFileFlags)
	proxyFlags.AddFlagSet(flags.DebugDontBlameOasisFlag)
	proxyFlags.AddFlagSet(flags.DebugAllowRootFlag)
	proxyFlags.AddFlagSet(pprof.Flags)
}
