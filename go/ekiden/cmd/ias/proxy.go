// Package ias implements the IAS sub commands.
package ias

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/ias"
	"github.com/oasislabs/ekiden/go/common/logging"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/background"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/grpc"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/metrics"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/common/pprof"
)

const ()

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

	authCertFile string
	authKeyFile  string
	authCertCA   string
	isProduction bool

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

	if authCertFile == "" {
		logger.Error("auth cert not configured")
		return
	}
	if authKeyFile == "" {
		logger.Error("auth key not configured")
		return
	}

	var err error

	// Initialize the gRPC server.
	env.grpcSrv, err = grpc.NewServer(cmd)
	if err != nil {
		logger.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(env.grpcSrv)

	// Initialize the metrics server.
	metrics, err := metrics.New(cmd)
	if err != nil {
		logger.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	env.svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := pprof.New(cmd)
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
	// TODO: Wire in authCertCA.
	endpoint, err := ias.NewIASEndpoint(authCertFile, authKeyFile, nil, isProduction)
	if err != nil {
		return err
	}

	ias.NewGRPCServer(env.grpcSrv.Server(), endpoint)

	logger.Debug("IAS proxy initialized")

	return nil
}

// Register registers the ias sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	iasProxyCmd.Flags().StringVar(&authCertFile, "auth_cert", "", "the file with the client certificate")
	iasProxyCmd.Flags().StringVar(&authKeyFile, "auth_key", "", "the file with the client private key")
	iasProxyCmd.Flags().StringVar(&authCertCA, "auth_cert_ca", "", "the file with the CA that signed the client certificate")
	iasProxyCmd.Flags().BoolVar(&isProduction, "production", false, "use the production IAS endpoint")

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
