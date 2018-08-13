package cmd

import (
	"context"
	"net"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/oasislabs/ekiden/go/common/service"
)

type metrics struct {
	service.BaseBackgroundService

	ln net.Listener
	s  *http.Server
}

func (s *metrics) Start() error {
	go func() {
		var ln net.Listener
		ln, s.ln = s.ln, nil
		err := s.s.Serve(ln)
		if err != nil {
			s.Logger.Error("metrics terminated uncleanly",
				"err", err,
			)
		}
		s.s = nil
		s.BaseBackgroundService.Stop()
	}()
	return nil
}

func (s *metrics) Stop() {
	if s.s != nil {
		s.s.Shutdown(context.Background())
		s.s = nil
	}
}

func (s *metrics) Cleanup() {
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func newMetrics(port uint16) (*metrics, error) {
	svc := *service.NewBaseBackgroundService("metrics")

	svc.Logger.Debug("Metric Server Params", "port", port)

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}

	return &metrics{
		BaseBackgroundService: svc,
		ln: ln,
		s:  &http.Server{Handler: promhttp.Handler()},
	}, nil
}
