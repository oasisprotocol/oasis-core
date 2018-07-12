package cmd

import (
	"net"
	"strconv"

	"google.golang.org/grpc"
)

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

func newGrpcService() (*grpcService, error) {
	rootLog.Debug("gRPC Server Params", "port", grpcPort)

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(grpcPort)))
	if err != nil {
		return nil, err
	}
	return &grpcService{
		ln:     ln,
		s:      grpc.NewServer(),
		quitCh: make(chan struct{}),
	}, nil
}
