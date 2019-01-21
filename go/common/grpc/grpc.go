// Package grpc implements common gRPC related services and utilities.
package grpc

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/service"
)

const (
	cfgGRPCVerboseDebug = "grpc.log.verbose_debug"

	maxRecvMsgSize = 104857600 // 100 MiB
	maxSendMsgSize = 104857600 // 100 MiB
)

var (
	grpcMetricsOnce sync.Once

	grpcCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_grpc_calls",
			Help: "Number of gRPC calls.",
		},
		[]string{"call"},
	)
	grpcLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_grpc_latency",
			Help: "gRPC call latency.",
		},
		[]string{"call"},
	)
	grpcStreamWrites = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_grpc_stream_writes",
			Help: "Number of gRPC stream writes",
		},
		[]string{"call"},
	)

	grpcCollectors = []prometheus.Collector{
		grpcCalls,
		grpcLatency,
		grpcStreamWrites,
	}

	_ grpclog.LoggerV2          = (*grpcLogAdapter)(nil)
	_ service.BackgroundService = (*Server)(nil)
)

type grpcLogAdapter struct {
	logger    *logging.Logger
	reqLogger *logging.Logger

	verbosity int
	reqSeq    uint64
	streamSeq uint64
	isDebug   bool
}

func (l *grpcLogAdapter) Info(args ...interface{}) {
	l.logger.Info(fmt.Sprint(args...))
}

func (l *grpcLogAdapter) Infoln(args ...interface{}) {
	l.logger.Info(fmt.Sprintln(args...))
}

func (l *grpcLogAdapter) Infof(format string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, args...))
}

func (l *grpcLogAdapter) Warning(args ...interface{}) {
	l.logger.Warn(fmt.Sprint(args...))
}

func (l *grpcLogAdapter) Warningln(args ...interface{}) {
	l.logger.Warn(fmt.Sprintln(args...))
}

func (l *grpcLogAdapter) Warningf(format string, args ...interface{}) {
	l.logger.Warn(fmt.Sprintf(format, args...))
}

func (l *grpcLogAdapter) Error(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...))
}

func (l *grpcLogAdapter) Errorln(args ...interface{}) {
	l.logger.Error(fmt.Sprintln(args...))
}

func (l *grpcLogAdapter) Errorf(format string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, args...))
}

func (l *grpcLogAdapter) Fatal(args ...interface{}) {
	l.logger.Error(fmt.Sprint(args...),
		"fatal", true,
	)
}

func (l *grpcLogAdapter) Fatalln(args ...interface{}) {
	l.logger.Error(fmt.Sprintln(args...),
		"fatal", true,
	)
}

func (l *grpcLogAdapter) Fatalf(format string, args ...interface{}) {
	l.logger.Error(fmt.Sprintf(format, args...),
		"fatal", true,
	)
}

func (l *grpcLogAdapter) V(level int) bool {
	return l.verbosity >= level
}

func (l *grpcLogAdapter) unaryLogger(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// TODO: Pull useful things out of ctx for logging.
	seq := atomic.AddUint64(&l.reqSeq, 1)
	if l.isDebug {
		l.reqLogger.Debug("request",
			"method", info.FullMethod,
			"req_seq", seq,
			"req", req,
		)
	}

	grpcCalls.With(prometheus.Labels{"call": info.FullMethod}).Inc()

	start := time.Now()
	resp, err = handler(ctx, req)
	grpcLatency.With(prometheus.Labels{"call": info.FullMethod}).Observe(time.Since(start).Seconds())
	switch err {
	case nil:
		if l.isDebug {
			l.reqLogger.Debug("request succeeded",
				"method", info.FullMethod,
				"req_seq", seq,
				"resp", resp,
			)
		}
	default:
		l.reqLogger.Error("request failed",
			"method", info.FullMethod,
			"req_seq", seq,
			"err", err,
		)
	}

	return
}

func (l *grpcLogAdapter) streamLogger(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	seq := atomic.AddUint64(&l.streamSeq, 1)
	if l.isDebug {
		l.reqLogger.Debug("stream",
			"method", info.FullMethod,
			"stream_seq", seq,
		)
	}

	stream := &grpcStreamLogger{
		ServerStream: ss,
		logAdapter:   l,
		method:       info.FullMethod,
		seq:          seq,
	}

	grpcCalls.With(prometheus.Labels{"call": info.FullMethod}).Inc()

	err := handler(srv, stream)

	if l.isDebug {
		switch err {
		case nil:
			l.reqLogger.Debug("stream closed",
				"method", info.FullMethod,
				"stream_seq", seq,
			)
		default:
			l.reqLogger.Error("stream closed (failure)",
				"method", info.FullMethod,
				"stream_seq", seq,
				"err", err,
			)
		}
	}

	return err
}

func newGrpcLogAdapter(baseLogger *logging.Logger) *grpcLogAdapter {
	grpcVerboseDebug := viper.GetBool(cfgGRPCVerboseDebug)

	// A extra 2 level 2 of unwinding since there's an adapter here,
	// and there's wrappers in the grpc library.
	//
	// Alas, transport/log.go also exists, so some places should
	// unwind 3 levels of stack calls, but this isn't something
	// that's easy to differentiate at runtime.
	return &grpcLogAdapter{
		logger:    logging.GetLoggerEx("grpc", 2),
		reqLogger: baseLogger,
		verbosity: 2,
		isDebug:   logging.GetLevel() == logging.LevelDebug && grpcVerboseDebug,
	}
}

type grpcStreamLogger struct {
	grpc.ServerStream

	logAdapter *grpcLogAdapter

	method string
	seq    uint64
}

func (s *grpcStreamLogger) SendMsg(m interface{}) error {
	grpcStreamWrites.With(prometheus.Labels{"call": s.method}).Inc()
	err := s.ServerStream.SendMsg(m)

	if s.logAdapter.isDebug {
		switch err {
		case nil:
			s.logAdapter.reqLogger.Debug("SendMsg",
				"method", s.method,
				"stream_seq", s.seq,
				"msg", m,
			)
		default:
			s.logAdapter.reqLogger.Debug("SendMsg failed",
				"method", s.method,
				"stream_seq", s.seq,
				"msg", m,
				"err", err,
			)
		}
	}

	return err
}

// Server is a gRPC server service.
type Server struct {
	service.BaseBackgroundService

	listener net.Listener
	server   *grpc.Server

	errCh chan error
}

// Start starts the Server.
func (s *Server) Start() error {
	s.Logger.Info("starting gRPC server")

	go func() {
		if err := s.server.Serve(s.listener); err != nil {
			s.BaseBackgroundService.Stop()
			s.errCh <- err
		}
	}()
	return nil
}

// Stop stops the Server.
func (s *Server) Stop() {
	if s.server != nil {
		select {
		case err := <-s.errCh:
			if err != nil {
				s.Logger.Error("gRPC Server terminated uncleanly",
					"err", err,
				)
			}
		default:
			s.server.GracefulStop()
		}
		s.server = nil
	}
}

// Cleanup cleans up after the Server.
func (s *Server) Cleanup() {
	if s.listener != nil {
		_ = s.listener.Close()
		s.listener = nil
	}
}

// Server returns the underlying gRPC server instance.
func (s *Server) Server() *grpc.Server {
	return s.server
}

// NewServerTCP constructs a new gRPC server service listening on
// a specific TCP port.
//
// This internally takes a snapshot of the current global tracer, so
// make sure you initialize the global tracer before calling this.
func NewServerTCP(name string, port uint16, cert *tls.Certificate) (*Server, error) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}

	return newServer(name, ln, cert)
}

// NewServerLocal constructs a new gRPC server service listening on
// a specific AF_LOCAL socket.
//
// This internally takes a snapshot of the current global tracer, so
// make sure you initialize the global tracer before calling this.
func NewServerLocal(name, path string) (*Server, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	return newServer(name, ln, nil)
}

func newServer(name string, listener net.Listener, cert *tls.Certificate) (*Server, error) {
	grpcMetricsOnce.Do(func() {
		prometheus.MustRegister(grpcCollectors...)
	})

	name = fmt.Sprintf("grpc/%s", name)
	svc := *service.NewBaseBackgroundService(name)
	logAdapter := newGrpcLogAdapter(svc.Logger)
	grpclog.SetLoggerV2(logAdapter)

	var sOpts []grpc.ServerOption
	sOpts = append(sOpts, grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(logAdapter.unaryLogger, grpc_opentracing.UnaryServerInterceptor())))
	sOpts = append(sOpts, grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(logAdapter.streamLogger, grpc_opentracing.StreamServerInterceptor())))
	sOpts = append(sOpts, grpc.MaxRecvMsgSize(maxRecvMsgSize))
	sOpts = append(sOpts, grpc.MaxSendMsgSize(maxSendMsgSize))

	if cert != nil {
		sOpts = append(sOpts, grpc.Creds(credentials.NewServerTLSFromCert(cert)))
	}

	return &Server{
		BaseBackgroundService: svc,
		listener:              listener,
		server:                grpc.NewServer(sOpts...),
		errCh:                 make(chan error),
	}, nil
}

// RegisterServerFlags registers the flags used by the gRPC server.
func RegisterServerFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgGRPCVerboseDebug, false, "gRPC request/responses in debug logs")
	}

	for _, v := range []string{
		cfgGRPCVerboseDebug,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
