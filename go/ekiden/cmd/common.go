package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"github.com/oasislabs/ekiden/go/common/logging"
	// TODO(willscott): wire in node for connectivity
	_ "github.com/oasislabs/ekiden/go/common/node"
	"github.com/spf13/viper"
)

func initCommon() {
	// Common initialization across all commands.
	initFns := []func() error{
		initDataDir,
		initLogging,
	}

	for _, fn := range initFns {
		if err := fn(); err != nil {
			logAndExit(err)
		}
	}

	rootLog.Debug("common initialization complete")
}

func initConfig() {
	if cfgFile != "" {
		// Read the config file if one is provided, otherwise
		// it is assumed that the combination of default values,
		// command line flags and env vars is sufficient.
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			logAndExit(err)
		}
	}

	// Force the DataDir to be an absolute path.
	var err error
	dataDir, err = filepath.Abs(viper.GetString(cfgDataDir))
	if err != nil {
		logAndExit(err)
	}

	// The command line flag values may be missing, but may be specified
	// from other sources, write back to the common flag vars for
	// convenience.
	//
	// Note: This is only for flags that are common across all
	// sub-commands, so excludes things such as the gRPC/Metrics/etc
	// configuration.
	viper.Set(cfgDataDir, dataDir)
	logFile = viper.GetString(cfgLogFile)
	logFmt = viper.GetString(cfgLogFmt)
	logLevel = viper.GetString(cfgLogLevel)
}

func initDataDir() error {
	const permDir = 0700

	// Tendermint uses dataDir/config, so we confim or make that subdirectory.
	fi, err := os.Lstat(path.Join(dataDir, "config"))
	if err != nil {
		if os.IsNotExist(err) {
			// Make the directory.
			if err = os.MkdirAll(path.Join(dataDir, "config"), permDir); err == nil {
				return nil
			}
		}
		return err
	}

	// Ensure the directory is actually a directory, with sufficiently
	// restrictive permissions.
	fm := fi.Mode()
	if !fm.IsDir() {
		return fmt.Errorf("init: datadir is not a directory")
	}
	if fm.Perm() != permDir {
		return fmt.Errorf("init: datadir has invalid permissions: %v", fm.Perm())
	}

	return nil
}

func initLogging() error {
	var w io.Writer = os.Stdout
	if logFile != "" {
		logFile = normalizePath(logFile)

		var err error
		if w, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err != nil {
			return err
		}
	}

	lvl, err := logging.LogLevel(logLevel)
	if err != nil {
		return err
	}
	f, err := logging.LogFormat(logFmt)
	if err != nil {
		return err
	}
	return logging.Initialize(w, lvl, f)
}

func logAndExit(err error) {
	fmt.Fprintln(os.Stderr, err) // nolint: errcheck
	os.Exit(1)
}

func normalizePath(f string) string {
	if !filepath.IsAbs(f) {
		f = filepath.Join(dataDir, f)
		return filepath.Clean(f)
	}
	return f
}

type cleanupAble interface {
	// Cleanup performs the service specific post-termination cleanup.
	Cleanup()
}

type backgroundService interface {
	// Stop halts the service.
	Stop()

	// Quit returns a channel that will be closed when the service terminates.
	Quit() <-chan struct{}

	cleanupAble
}

type cleanupOnlyService struct {
	svc cleanupAble
}

func (s *cleanupOnlyService) Stop() {
	// Nothing to stop.
}

func (s *cleanupOnlyService) Quit() <-chan struct{} {
	panic("BUG: cleanupOnlyService does not implement Quit()")
}

func (s *cleanupOnlyService) Cleanup() {
	s.svc.Cleanup()
}

type backgroundServiceManager struct {
	services []backgroundService
	termCh   chan backgroundService
	termSvc  backgroundService
}

func (m *backgroundServiceManager) Register(srv backgroundService) {
	m.services = append(m.services, srv)
	go func() {
		<-srv.Quit()
		select {
		case m.termCh <- srv:
		default:
		}
	}()
}

func (m *backgroundServiceManager) RegisterCleanupOnly(svc cleanupAble) {
	s := &cleanupOnlyService{svc: svc}
	m.services = append(m.services, s)
}

func (m *backgroundServiceManager) Wait() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case m.termSvc = <-m.termCh:
		rootLog.Info("background task terminated, propagating")
	case <-sigCh:
		rootLog.Info("user requested termination")
	}

	for _, svc := range m.services {
		if svc != m.termSvc {
			svc.Stop()
		}
	}
}

func (m *backgroundServiceManager) Cleanup() {
	rootLog.Debug("terminating, begining cleanup")

	for _, svc := range m.services {
		svc.Cleanup()
	}

	rootLog.Debug("finished cleanup")
}

func newBackgroundServiceManager() *backgroundServiceManager {
	return &backgroundServiceManager{
		termCh: make(chan backgroundService),
	}
}
