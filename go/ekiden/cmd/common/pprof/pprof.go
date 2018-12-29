// Package pprof implements a pprof profiling service.
package pprof

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/service"
)

const cfgPprofBind = "pprof.bind"

var pprofBind string

type pprofService struct {
	service.BaseBackgroundService

	address string

	listener net.Listener
	server   *http.Server

	errCh chan error
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
	p.server = &http.Server{Handler: mux}

	go func() {
		if err := p.server.Serve(p.listener); err != nil {
			p.BaseBackgroundService.Stop()
			p.errCh <- err
		}
	}()

	return nil
}

func (p *pprofService) Stop() {
	if p.server != nil {
		select {
		case err := <-p.errCh:
			if err != nil {
				p.Logger.Error("pprof server terminated uncleanly",
					"err", err,
				)
			}
		default:
			_ = p.server.Shutdown(context.Background())
		}
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
	address := viper.GetString(cfgPprofBind)

	return &pprofService{
		BaseBackgroundService: *service.NewBaseBackgroundService("pprof"),
		address:               address,
		errCh:                 make(chan error),
	}, nil
}

// RegisterFlags registers the flags used by the pprof service.
func RegisterFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&pprofBind, cfgPprofBind, "", "enable profiling endpoint at given address")

	for _, v := range []string{
		cfgPprofBind,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
