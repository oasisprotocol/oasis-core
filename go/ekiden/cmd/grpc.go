package cmd

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/service"
)

const cfgGRPCPort = "grpc.port"

var (
	grpcPort        uint16
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

	_ grpclog.LoggerV2 = (*grpcLogAdapter)(nil)
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
		l.reqLogger.Debug("request succeeded",
			"method", info.FullMethod,
			"req_seq", seq,
			"resp", resp,
		)
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
		isDebug:   logging.GetLevel() == logging.LevelDebug,
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

func newGrpcService(cmd *cobra.Command) (*grpcService, error) {
	grpcMetricsOnce.Do(func() {
		prometheus.MustRegister(grpcCollectors...)
	})

	port, _ := cmd.Flags().GetUint16(cfgGRPCPort)

	svc := *service.NewBaseBackgroundService("grpc")

	svc.Logger.Debug("gRPC Server Params", "port", port)

	ln, err := net.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}

	logAdapter := newGrpcLogAdapter(svc.Logger)
	grpclog.SetLoggerV2(logAdapter)

	var sOpts []grpc.ServerOption
	sOpts = append(sOpts, grpc.UnaryInterceptor(logAdapter.unaryLogger))
	sOpts = append(sOpts, grpc.StreamInterceptor(logAdapter.streamLogger))

	return &grpcService{
		BaseBackgroundService: svc,
		ln:                    ln,
		s:                     grpc.NewServer(sOpts...),
	}, nil
}

func registerGrpcFlags(cmd *cobra.Command) {
	// Flags specific to the root command.
	cmd.Flags().Uint16Var(&grpcPort, cfgGRPCPort, 9001, "gRPC server port")

	for _, v := range []string{
		cfgGRPCPort,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
