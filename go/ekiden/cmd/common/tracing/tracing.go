// Package tracing implements a tracing service.
package tracing

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	jaegercfg "github.com/uber/jaeger-client-go/config"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/service"
)

const (
	cfgTracingEnabled                    = "tracing.enabled"
	cfgTracingReporterFlushInterval      = "tracing.reporter.flush_interval"
	cfgTracingReporterLocalAgentHostPort = "tracing.reporter.agent_addr"
	cfgTracingSamplerParam               = "tracing.sampler.param"
)

// ServiceConfig contains the configuration parameters for tracing.
type ServiceConfig struct {
	// Enabled is true if the service is enabled.
	Enabled bool
	// FlushInterval
	FlushInterval time.Duration
	// AgentAddress is the address of the tracing server.
	AgentAddress string
	// SamplerParam
	SamplerParam float64
}

// GetServiceConfig gets the tracing configuration parameter struct.
func GetServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		Enabled:       viper.GetBool(cfgTracingEnabled),
		FlushInterval: viper.GetDuration(cfgTracingReporterFlushInterval),
		AgentAddress:  viper.GetString(cfgTracingReporterLocalAgentHostPort),
		SamplerParam:  viper.GetFloat64(cfgTracingSamplerParam),
	}
}

type tracingService struct {
	closer io.Closer
}

func (svc *tracingService) Cleanup() {
	if svc.closer != nil {
		svc.closer.Close()
		svc.closer = nil
	}
}

// Our logging adapter for opentracing.
type ekidenTracingLogger struct {
	logger *logging.Logger
}

func (l *ekidenTracingLogger) Error(msg string) {
	l.logger.Error(msg)
}

func (l *ekidenTracingLogger) Infof(msg string, args ...interface{}) {
	l.logger.Info(fmt.Sprintf(msg, args))
}

// New constructs a new tracing service.
func New(serviceName string) (service.CleanupAble, error) {
	enabled := viper.GetBool(cfgTracingEnabled)
	reporterFlushInterval := viper.GetDuration(cfgTracingReporterFlushInterval)
	reporterLocalAgentHostPort := viper.GetString(cfgTracingReporterLocalAgentHostPort)
	samplerParam := viper.GetFloat64(cfgTracingSamplerParam)

	cfg := jaegercfg.Configuration{
		Disabled: !enabled,
		Reporter: &jaegercfg.ReporterConfig{
			BufferFlushInterval: reporterFlushInterval,
			LocalAgentHostPort:  reporterLocalAgentHostPort,
		},
		Sampler: &jaegercfg.SamplerConfig{
			Param: samplerParam,
		},
	}

	closer, err := cfg.InitGlobalTracer(serviceName, jaegercfg.Logger(&ekidenTracingLogger{logger: logging.GetLogger("ekiden/cmd/common/tracing")}))
	if err != nil {
		return nil, err
	}

	return &tracingService{closer: closer}, nil
}

// RegisterFlags registers the flags used by the tracing service.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgTracingEnabled, false, "Enable tracing")
		cmd.Flags().Duration(cfgTracingReporterFlushInterval, 1*time.Second, "How often the buffer is force-flushed, even if it's not full")
		cmd.Flags().String(cfgTracingReporterLocalAgentHostPort, "jaeger:6831", "Send spans to jaeger-agent at this address")
		cmd.Flags().Float64(cfgTracingSamplerParam, 1.0, "Probability for probabilistic sampler")
	}

	for _, v := range []string{
		cfgTracingEnabled,
		cfgTracingReporterFlushInterval,
		cfgTracingReporterLocalAgentHostPort,
		cfgTracingSamplerParam,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
