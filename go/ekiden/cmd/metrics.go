// Implements a metrics endpoint for the services.
package cmd

import (
	"context"
	"net"
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	ln     net.Listener
	s      *http.Server
	quitCh chan struct{}
}

func (s *metrics) Start() error {
	go func() {
		var ln net.Listener
		ln, s.ln = s.ln, nil
		err := s.s.Serve(ln)
		if err != nil {
			rootLog.Error("metrics terminated uncleanly",
				"err", err,
			)
		}
		s.s = nil
		close(s.quitCh)
	}()
	return nil
}

func (s *metrics) Quit() <-chan struct{} {
	return s.quitCh
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
	rootLog.Debug("Metric Server Params", "port", port)

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}

	return &metrics{
		ln:     ln,
		s:      &http.Server{Handler: promhttp.Handler()},
		quitCh: make(chan struct{}),
	}, nil
}
