package cmd

import (
	"net"
	"strconv"

	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/service"
)

type grpcService struct {
	service.BaseBackgroundService

	ln net.Listener
	s  *grpc.Server
}

func (s *grpcService) Start() error {
	go func() {
		var ln net.Listener
		ln, s.ln = s.ln, nil
		err := s.s.Serve(ln)
		if err != nil {
			s.Logger.Error("gRPC Server terminated uncleanly",
				"err", err,
			)
		}
		s.s = nil
		s.BaseBackgroundService.Stop()
	}()
	return nil
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
	svc := *service.NewBaseBackgroundService("grpc")

	svc.Logger.Debug("gRPC Server Params", "port", grpcPort)

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}
	return &grpcService{
		BaseBackgroundService: svc,
		ln: ln,
		s:  grpc.NewServer(),
	}, nil
}
