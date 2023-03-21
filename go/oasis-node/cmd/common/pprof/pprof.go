// Package pprof implements a pprof profiling service.
package pprof

import (
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"time"

	runtimePprof "runtime/pprof"

	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/config"
)

type pprofService struct {
	service.BaseBackgroundService

	address string

	listener net.Listener
	server   *http.Server
}

// DumpHeapToFile writes the current process heap to given file with unique suffix.
func DumpHeapToFile(name string) error {
	// Find unique filename.
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to determine current working directory for memory profiler output: %w", err)
	}
	mprof, merr := os.CreateTemp(wd, name+".*.pb")
	if merr != nil {
		return fmt.Errorf("failed to create file for memory profiler output: %w", merr)
	}
	defer mprof.Close()

	// Write memory profiling data.
	runtime.GC()
	if merr = runtimePprof.WriteHeapProfile(mprof); merr != nil {
		return fmt.Errorf("failed to write heap profile: %w", merr)
	}

	return nil
}

func (p *pprofService) Start() error {
	if p.address == "" {
		return nil
	}

	p.Logger.Info("profiling HTTP endpoint is enabled",
		"address", p.address,
	)

	listener, err := net.Listen("tcp", p.address)
	if err != nil {
		return err
	}

	// Create a new mux just for the pprof endpoints to avoid using the
	// global multiplexer where pprof's init function registers by default.
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	p.listener = listener
	p.server = &http.Server{Handler: mux, ReadTimeout: 5 * time.Second}

	go func() {
		if err := p.server.Serve(p.listener); err != nil {
			if err != http.ErrServerClosed {
				p.Logger.Error("pprof server terminated uncleanly",
					"err", err,
				)
			}
		}
		p.BaseBackgroundService.Stop()
	}()

	return nil
}

func (p *pprofService) Stop() {
	// If we never started, make sure that the service doesn't hang forever.
	if p.address == "" {
		p.BaseBackgroundService.Stop()
		return
	}

	if p.server != nil {
		_ = p.server.Close()
		p.server = nil
	}
}

func (p *pprofService) Cleanup() {
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}
}

// New constructs a new pprof service.
func New() (service.BackgroundService, error) {
	address := config.GlobalConfig.Pprof.BindAddress

	return &pprofService{
		BaseBackgroundService: *service.NewBaseBackgroundService("pprof"),
		address:               address,
	}, nil
}
