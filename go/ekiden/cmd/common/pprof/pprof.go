// Package pprof implements a pprof profiling service.
package pprof

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/service"
)

const cfgPprofBind = "pprof.bind"

// Flags has our flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

type pprofService struct {
	service.BaseBackgroundService

	address string

	listener net.Listener
	server   *http.Server

	ctx   context.Context
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
			_ = p.server.Shutdown(p.ctx)
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
func New(ctx context.Context) (service.BackgroundService, error) {
	address := viper.GetString(cfgPprofBind)

	return &pprofService{
		BaseBackgroundService: *service.NewBaseBackgroundService("pprof"),
		address:               address,
		ctx:                   ctx,
		errCh:                 make(chan error),
	}, nil
}

// RegisterFlags registers the flags used by the pprof service.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().AddFlagSet(Flags)
	}
}

func init() {
	Flags.String(cfgPprofBind, "", "enable profiling endpoint at given address")

	_ = viper.BindPFlags(Flags)
}
