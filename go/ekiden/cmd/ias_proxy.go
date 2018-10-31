package cmd

import (
	"github.com/spf13/cobra"

	"github.com/oasislabs/ekiden/go/common/ias"
	"github.com/oasislabs/ekiden/go/common/logging"
)

var (
	authCertFile string
	authKeyFile string
	authCertCA string
	isProduction bool

	iasProxyCommand = &cobra.Command{
		Use:   "ias-proxy",
		Short: "forward IAS requests under given client credentials",
		Run:   iasProxy,
	}

	iasProxyLog = logging.GetLogger("ias-proxy")
)

func iasProxy(cmd *cobra.Command, args []string) {
	svcMgr := newBackgroundServiceManager()
	defer svcMgr.Cleanup()

	initCommon()

	if authCertFile == "" {
		iasProxyLog.Error("auth cert not configured")
		return
	}
	if authKeyFile == "" {
		iasProxyLog.Error("auth key not configured")
		return
	}

	// Initialize the gRPC server.
	grpcSrv, err := newGrpcService(cmd)
	if err != nil {
		iasProxyLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	svcMgr.Register(grpcSrv)

	// Initialize the metrics server.
	metrics, err := newMetrics(cmd)
	if err != nil {
		iasProxyLog.Error("failed to initialize metrics server",
			"err", err,
		)
		return
	}
	svcMgr.Register(metrics)

	// Initialize the profiling server.
	profiling, err := newPprofService(cmd)
	if err != nil {
		iasProxyLog.Error("failed to initialize pprof server",
			"err", err,
		)
		return
	}
	svcMgr.Register(profiling)

	// Start the profiling server.
	if err = profiling.Start(); err != nil {
		iasProxyLog.Error("failed to start pprof server",
			"err", err,
		)
		return
	}

	// Initialize the IAS proxy.
	if err = initIasProxy(cmd, svcMgr, grpcSrv); err != nil {
		iasProxyLog.Error("failed to initialize IAS proxy",
			"err", err,
		)
		return
	}

	// Start metric server.
	if err = metrics.Start(); err != nil {
		iasProxyLog.Error("failed to start metric server",
			"err", err,
		)
		return
	}

	// Start the gRPC server.
	if err = grpcSrv.Start(); err != nil {
		iasProxyLog.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	iasProxyLog.Info("initialization complete: ready to serve")

	// Wait for the services to catch on fire or otherwise
	// terminate.
	svcMgr.Wait()
}

func initIasProxy(cmd *cobra.Command, svcMgr *backgroundServiceManager, grpcSrv *grpcService) error {
	endpoint, err := ias.NewIASEndpoint(authCertFile, authKeyFile, nil, isProduction)
	if err != nil {
		return err
	}

	ias.NewGRPCServer(grpcSrv.s, endpoint)

	iasProxyLog.Debug("IAS proxy initialized")

	return nil
}

func init() {
	iasProxyCommand.Flags().StringVar(&authCertFile, "auth-cert", "", "the file with the client certificate")
	iasProxyCommand.Flags().StringVar(&authKeyFile, "auth-key", "", "the file with the client private key")
	iasProxyCommand.Flags().StringVar(&authCertCA, "auth-cert-ca", "", "the file with the CA that signed the client certificate")
	iasProxyCommand.Flags().BoolVar(&isProduction, "production", false, "use the production IAS endpoint")

	rootCmd.AddCommand(iasProxyCommand)

	for _, v := range []func(*cobra.Command){
		registerMetricsFlags,
		registerGrpcFlags,
		registerPprofFlags,
	} {
		v(iasProxyCommand)
	}
}
