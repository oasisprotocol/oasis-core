// Package grpc implements common gRPC related services and utilities.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_opentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	"github.com/prometheus/client_golang/prometheus"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/keepalive"

	"github.com/oasislabs/oasis-core/go/common/grpc/auth"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/service"
)

const (
	// CfgLogDebug enables verbose gRPC debug output.
	CfgLogDebug = "grpc.log.debug"

	maxRecvMsgSize = 104857600 // 100 MiB
	maxSendMsgSize = 104857600 // 100 MiB
)

var (
	// Flags has the flags used by the gRPC server.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	grpcMetricsOnce      sync.Once
	grpcGlobalLoggerOnce sync.Once

	grpcCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_grpc_calls",
			Help: "Number of gRPC calls.",
		},
		[]string{"call"},
	)
	grpcLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_grpc_latency",
			Help: "gRPC call latency.",
		},
		[]string{"call"},
	)
	grpcStreamWrites = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_grpc_stream_writes",
			Help: "Number of gRPC stream writes",
		},
		[]string{"call"},
	)

	grpcCollectors = []prometheus.Collector{
		grpcCalls,
		grpcLatency,
		grpcStreamWrites,
	}

	serverKeepAliveParams = keepalive.ServerParameters{
		MaxConnectionIdle: 600 * time.Second,
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
	logDebug := viper.GetBool(CfgLogDebug)

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
		isDebug:   logging.GetLevel() == logging.LevelDebug && logDebug,
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
				"message", m,
			)
		default:
			s.logAdapter.reqLogger.Debug("SendMsg failed",
				"method", s.method,
				"stream_seq", s.seq,
				"message", m,
				"err", err,
			)
		}
	}

	return err
}

// Server is a gRPC server service.
type Server struct {
	sync.Mutex
	service.BaseBackgroundService

	listenerCfgs     []listenerConfig
	startedListeners []net.Listener
	server           *grpc.Server
	errCh            chan error

	unsafeDebug bool

	wrapper *grpcWrapper
}

// ServerConfig holds the configuration used for creating a server.
type ServerConfig struct { // nolint: maligned
	// Name of the server being constructed.
	Name string
	// Port is the port used for TCP servers.
	//
	// Iff Path is not empty (i.e. a local server is being created), and Port is not 0, then
	// the local server will *also* listen on that port.
	Port uint16
	// Path is the path for the local server. Leave nil to create a TCP server.
	Path string
	// Certificate is the certificate used by the server. Should be nil for local servers.
	Certificate *tls.Certificate
	// InstallWrapper specifies whether intercepting facilities should be enabled on this server,
	// to enable intercepting RPC calls with a wrapper.
	InstallWrapper bool
	AuthFunc       auth.AuthenticationFunction
	// CustomOptions is an array of extra options for the grpc server.
	CustomOptions []grpc.ServerOption
}

type listenerConfig struct {
	network string
	address string
}

// Start starts the Server.
func (s *Server) Start() error {
	s.Lock()
	defer s.Unlock()

	if s.server == nil {
		// Could happen if Stop is called before Start.
		return fmt.Errorf("gRPC server has already been stopped")
	}
	server := s.server

	s.Logger.Info("starting gRPC server")
	if s.unsafeDebug {
		s.Logger.Warn("The debug gRPC port is NOT FOR PRODUCTION USE.")
	}

	for _, v := range s.listenerCfgs {
		cfg := v

		ln, err := net.Listen(cfg.network, cfg.address)
		if err != nil {
			s.Logger.Error("error starting gRPC server",
				"error", err,
			)
			return err
		}
		s.startedListeners = append(s.startedListeners, ln)

		go func() {
			if err := server.Serve(ln); err != nil {
				s.BaseBackgroundService.Stop()
				s.errCh <- err
			}
		}()
	}

	return nil
}

// Stop stops the Server.
func (s *Server) Stop() {
	s.Lock()
	defer s.Unlock()

	if s.server != nil {
		select {
		case err := <-s.errCh:
			// Only the first error will get logged, probably ok?
			if err != nil {
				s.Logger.Error("gRPC Server terminated uncleanly",
					"err", err,
				)
			}
		default:
		}
		s.server.GracefulStop() // Repeated calls are ok.
		s.server = nil
	}
}

// Cleanup cleans up after the Server.
func (s *Server) Cleanup() {
	s.Lock()
	defer s.Unlock()

	for _, v := range s.startedListeners {
		_ = v.Close()
	}
	s.startedListeners = nil
}

// Server returns the underlying gRPC server instance.
func (s *Server) Server() *grpc.Server {
	return s.server
}

// NewServer constructs a new gRPC server service listening on
// a specific TCP port or local socket path.
//
// This internally takes a snapshot of the current global tracer, so
// make sure you initialize the global tracer before calling this.
func NewServer(config *ServerConfig) (*Server, error) {
	var listenerParams []listenerConfig
	var clientAuthType tls.ClientAuthType
	unsafeDebug := false

	if config.Path == "" {
		// Public TCP server.
		cfg := listenerConfig{
			network: "tcp",
			address: ":" + strconv.Itoa(int(config.Port)),
		}
		listenerParams = []listenerConfig{cfg}
		clientAuthType = tls.RequestClientCert
	} else {
		// Local server.

		// Remove any existing socket files first.
		_ = os.Remove(config.Path)

		listenerParams = append(listenerParams, listenerConfig{
			network: "unix",
			address: config.Path,
		})
		if config.Port != 0 {
			listenerParams = append(listenerParams, listenerConfig{
				network: "tcp",
				address: ":" + strconv.Itoa(int(config.Port)),
			})
			unsafeDebug = true
		}

		clientAuthType = tls.NoClientCert
	}

	grpcMetricsOnce.Do(func() {
		prometheus.MustRegister(grpcCollectors...)
	})

	grpcGlobalLoggerOnce.Do(func() {
		logger := logging.GetLogger("grpc")
		logAdapter := newGrpcLogAdapter(logger)
		grpclog.SetLoggerV2(logAdapter)
	})

	name := fmt.Sprintf("grpc/%s", config.Name)
	svc := *service.NewBaseBackgroundService(name)
	logAdapter := newGrpcLogAdapter(svc.Logger)

	if config.AuthFunc == nil {
		// Default to NoAuth.
		config.AuthFunc = auth.NoAuth
	}
	var sOpts []grpc.ServerOption
	var wrapper *grpcWrapper
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		logAdapter.unaryLogger,
		grpc_opentracing.UnaryServerInterceptor(),
		serverUnaryErrorMapper,
		auth.UnaryServerInterceptor(config.AuthFunc),
	}
	streamInterceptors := []grpc.StreamServerInterceptor{
		logAdapter.streamLogger,
		grpc_opentracing.StreamServerInterceptor(),
		serverStreamErrorMapper,
		auth.StreamServerInterceptor(config.AuthFunc),
	}
	if config.InstallWrapper {
		wrapper = newWrapper()
		unaryInterceptors = append(unaryInterceptors, wrapper.unaryInterceptor)
		streamInterceptors = append(streamInterceptors, wrapper.streamInterceptor)
	}
	sOpts = append(sOpts, grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(unaryInterceptors...)),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(streamInterceptors...))),
		grpc.MaxRecvMsgSize(maxRecvMsgSize),
		grpc.MaxSendMsgSize(maxSendMsgSize),
		grpc.KeepaliveParams(serverKeepAliveParams),
		grpc.CustomCodec(&CBORCodec{})
	sOpts = append(sOpts, config.CustomOptions...)

	if config.Certificate != nil {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*config.Certificate},
			ClientAuth:   clientAuthType,
		}
		sOpts = append(sOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	return &Server{
		BaseBackgroundService: svc,
		listenerCfgs:          listenerParams,
		startedListeners:      []net.Listener{},
		server:                grpc.NewServer(sOpts...),
		errCh:                 make(chan error, len(listenerParams)),
		unsafeDebug:           unsafeDebug,
		wrapper:               wrapper,
	}, nil
}

// Dial creates a client connection to the given target.
func Dial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append(opts, grpc.WithDefaultCallOptions(
		grpc.ForceCodec(&CBORCodec{}),
	))
	opts = append(opts, grpc.WithChainUnaryInterceptor(clientUnaryErrorMapper))
	opts = append(opts, grpc.WithChainStreamInterceptor(clientStreamErrorMapper))
	return grpc.Dial(target, opts...)
}

func init() {
	Flags.Bool(CfgLogDebug, false, "gRPC request/responses in debug logs (very verbose)")
	_ = Flags.MarkHidden(CfgLogDebug)

	_ = viper.BindPFlags(Flags)
}
