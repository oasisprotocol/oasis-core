// Package ias implements the IAS sub commands.
package ias

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/ias"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/metrics"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/pprof"
)

const (
	cfgAuthCertFile = "auth_cert"
	cfgAuthKeyFile  = "auth_key"
	cfgAuthCertCA   = "auth_cert_ca"
	cfgSPID         = "spid"
	cfgQuoteSigType = "quote_signature_type"
	cfgIsProduction = "production"
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
	}

	flagAuthCertFile string
	flagAuthKeyFile  string
	flagAuthCertCA   string
	flagSpid         string
	flagQuoteSigType string
	flagIsProduction bool

	logger = logging.GetLogger("cmd/ias/proxy")
)

type proxyEnv struct {
	svcMgr  *background.ServiceManager
	grpcSrv *grpc.Server
}

func doProxy(cmd *cobra.Command, args []string) {
	env := &proxyEnv{
		svcMgr: background.NewServiceManager(logger),
	}
	defer func() { env.svcMgr.Cleanup() }()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	if flagAuthCertFile == "" {
		logger.Error("auth cert not configured")
		return
	}
	if flagAuthKeyFile == "" {
		logger.Error("auth key not configured")
		return
	}

	var err error

	// Initialize the gRPC server.
	env.grpcSrv, err = grpc.NewServer()
	if err != nil {
		logger.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metrics, err := metrics.New()
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := pprof.New()
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

	// Initialize the IAS proxy.
	if err = initProxy(cmd, env); err != nil {
		logger.Error("failed to initialize IAS proxy",
			"err", err,
		)
		return

	}

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

	logger.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	env.svcMgr.Wait()
}

func initProxy(cmd *cobra.Command, env *proxyEnv) error {
	var quoteSigType ias.SignatureType
	switch strings.ToLower(flagQuoteSigType) {
	case "unlinkable":
		quoteSigType = ias.SignatureUnlinkable
	case "linkable":
		quoteSigType = ias.SignatureLinkable
	default:
		return fmt.Errorf("ias: invalid signature type: %s", flagQuoteSigType)
	}

	var authCertCA *x509.Certificate
	if flagAuthCertCA != "" {
		certData, err := ioutil.ReadFile(flagAuthCertCA)
		if err != nil {
			return err
		}

		authCertCA, _, err = ias.CertFromPEM(certData)
		if err != nil {
			return err
		}
	}

	endpoint, err := ias.NewIASEndpoint(
		flagAuthCertFile,
		flagAuthKeyFile,
		authCertCA,
		flagSpid,
		quoteSigType,
		flagIsProduction,
	)
	if err != nil {
		return err
	}

	ias.NewGRPCServer(env.grpcSrv.Server(), endpoint)

	logger.Debug("IAS proxy initialized")

	return nil
}

// Register registers the ias sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	iasProxyCmd.Flags().StringVar(&flagAuthCertFile, cfgAuthCertFile, "", "the file with the client certificate")
	iasProxyCmd.Flags().StringVar(&flagAuthKeyFile, cfgAuthKeyFile, "", "the file with the client private key")
	iasProxyCmd.Flags().StringVar(&flagAuthCertCA, cfgAuthCertCA, "", "the file with the CA that signed the client certificate")
	iasProxyCmd.Flags().StringVar(&flagSpid, cfgSPID, "", "SPID associated with the client certificate")
	iasProxyCmd.Flags().StringVar(&flagQuoteSigType, cfgQuoteSigType, "linkable", "quote signature type associated with the SPID")
	iasProxyCmd.Flags().BoolVar(&flagIsProduction, cfgIsProduction, false, "use the production IAS endpoint")

	for _, v := range []string{
		cfgAuthCertFile,
		cfgAuthKeyFile,
		cfgAuthCertCA,
		cfgSPID,
		cfgQuoteSigType,
		cfgIsProduction,
	} {
		viper.BindPFlag(v, iasProxyCmd.Flags().Lookup(v)) // nolint: errcheck
	}

	for _, v := range []func(*cobra.Command){
		metrics.RegisterFlags,
		grpc.RegisterServerFlags,
		pprof.RegisterFlags,
	} {
		v(iasProxyCmd)
	}

	iasCmd.AddCommand(iasProxyCmd)
	parentCmd.AddCommand(iasCmd)
}
