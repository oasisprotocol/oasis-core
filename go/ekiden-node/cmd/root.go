// Package cmd implements the commands for the ekiden-node executable.
package cmd

import (
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/tendermint/abci"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

const (
	cfgDataDir  = "datadir"
	cfgLogFile  = "log.file"
	cfgLogFmt   = "log.format"
	cfgLogLevel = "log.level"

	cfgABCIAddr = "abci.address"
	cfgABCIPort = "abci.port"
	cfgGRPCPort = "grpc.port"
)

var (
	cfgFile  string
	dataDir  string
	logFile  string
	logFmt   string
	logLevel string

	abciAddr net.IP
	abciPort uint16

	grpcPort uint16

	rootCmd = &cobra.Command{
		Use:     "ekiden-node",
		Short:   "Ekiden node",
		Version: "0.2.0-alpha",
		Run:     rootMain,
	}

	rootLog = logging.GetLogger("ekiden-node")
)

// Execute spawns the main entry point after handling the config file
// and command line arguments.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logAndExit(err)
	}
}

func rootMain(cmd *cobra.Command, args []string) {
	initCommon()

	var cleanupFns []func()
	defer func() {
		rootLog.Debug("terminating, begining cleanup")

		for _, fn := range cleanupFns {
			fn()
		}

		rootLog.Debug("terminated")
	}()

	// XXX: Generate/Load the node identity.
	// Except tendermint does this on it's own, sigh.

	// Initialze the gRPC server.
	rootLog.Debug("gRPC Server Params", "port", grpcPort)
	grpcSrv, err := newGrpcService(grpcPort)
	if err != nil {
		rootLog.Error("failed to initialize gRPC server",
			"err", err,
		)
		return
	}
	cleanupFns = append(cleanupFns, grpcSrv.Cleanup)

	// Initialize the ABCI multiplexer.
	abciSockAddr := net.JoinHostPort(abciAddr.String(), strconv.Itoa(int(abciPort)))
	rootLog.Debug("ABCI Multiplexer Params", "addr", abciSockAddr)

	mux, err := abci.NewApplicationServer(abciSockAddr, dataDir)
	if err != nil {
		rootLog.Error("failed to initialize ABCI multiplexer",
			"err", err,
		)
		return
	}
	cleanupFns = append(cleanupFns, mux.Cleanup)

	// XXX: Register the various services with the ABCI multiplexer.
	_ = mux

	// Start the ABCI server.
	if err = mux.Start(); err != nil {
		rootLog.Error("failed to start ABCI multiplexer",
			"err", err,
		)
		return
	}

	// Start the gRPC server.
	if err = grpcSrv.Start(); err != nil {
		rootLog.Error("failed to start gRPC server",
			"err", err,
		)
		return
	}

	// TODO: Spin up the tendermint node.
	// This should be in-process rather than fork() + exec() based.

	// Wait for the services to catch on fire or otherwise
	// terminate.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sigCh:
		grpcSrv.Stop()
		mux.Stop()
		break
	case <-mux.Quit():
		grpcSrv.Stop()
		break
	case <-grpcSrv.Quit():
		mux.Stop()
		break
	}
}

type grpcService struct {
	ln     net.Listener
	s      *grpc.Server
	quitCh chan struct{}
}

func (s *grpcService) Start() error {
	go func() {
		var ln net.Listener
		ln, s.ln = s.ln, nil
		err := s.s.Serve(ln)
		if err != nil {
			rootLog.Error("gRPC Server terminated uncleanly",
				"err", err,
			)
		}
		s.s = nil
		close(s.quitCh)
	}()
	return nil
}

func (s *grpcService) Quit() <-chan struct{} {
	return s.quitCh
}

func (s *grpcService) Stop() {
	if s.s != nil {
		s.s.GracefulStop()
		s.s = nil
	}
}

func (s *grpcService) Cleanup() {
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func newGrpcService(port uint16) (*grpcService, error) {
	ln, err := net.Listen("tcp", strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}
	return &grpcService{
		ln:     ln,
		s:      grpc.NewServer(),
		quitCh: make(chan struct{}),
	}, nil
}

// nolint: errcheck
func init() {
	cobra.OnInitialize(initConfig)

	// Global flags common across all commands.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file")
	rootCmd.PersistentFlags().StringVar(&dataDir, cfgDataDir, "", "data directory")
	rootCmd.PersistentFlags().StringVar(&logFile, cfgLogFile, "", "log file")
	rootCmd.PersistentFlags().StringVar(&logFmt, cfgLogFmt, "Logfmt", "log format")
	rootCmd.PersistentFlags().StringVar(&logLevel, cfgLogLevel, "INFO", "log level")
	rootCmd.MarkPersistentFlagRequired(cfgDataDir)

	for _, v := range []string{
		cfgDataDir,
		cfgLogFile,
		cfgLogFmt,
		cfgLogLevel,
	} {
		viper.BindPFlag(v, rootCmd.PersistentFlags().Lookup(v))
	}

	// Flags specific to the root command.
	rootCmd.Flags().IPVar(&abciAddr, cfgABCIAddr, net.IPv4(127, 0, 0, 1), "ABCI server IP address")
	rootCmd.Flags().Uint16Var(&abciPort, cfgABCIPort, 26658, "ABCI server port")
	rootCmd.Flags().Uint16Var(&grpcPort, cfgGRPCPort, 26659, "gRPC server port")

	for _, v := range []string{
		cfgABCIAddr,
		cfgABCIPort,
		cfgGRPCPort,
	} {
		viper.BindPFlag(v, rootCmd.Flags().Lookup(v))
	}
}
