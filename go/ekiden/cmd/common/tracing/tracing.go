// Package tracing implements a tracing service.
package tracing

import (
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"

	"github.com/oasislabs/ekiden/go/common/service"
)

const (
	cfgTracingEnabled                    = "tracing.enabled"
	cfgTracingReporterFlushInterval      = "tracing.reporter.flush_interval"
	cfgTracingReporterLocalAgentHostPort = "tracing.reporter.agent_addr"
	cfgTracingSamplerParam               = "tracing.sampler.param"
)

type tracingService struct {
	closer io.Closer
}

func (svc *tracingService) Cleanup() {
	if svc.closer != nil {
		svc.closer.Close()
		svc.closer = nil
	}
}

// New constructs a new tracing service.
func New(serviceName string) (service.CleanupAble, error) {
	enabled := viper.GetBool(cfgTracingEnabled)
	reporterFlushInterval := viper.GetDuration(cfgTracingReporterFlushInterval)
	reporterLocalAgentHostPort := viper.GetString(cfgTracingReporterLocalAgentHostPort)
	samplerParam := viper.GetFloat64(cfgTracingSamplerParam)

	cfg := config.Configuration{
		Disabled: !enabled,
		Reporter: &config.ReporterConfig{
			BufferFlushInterval: reporterFlushInterval,
			LocalAgentHostPort:  reporterLocalAgentHostPort,
		},
		Sampler: &config.SamplerConfig{
			Param: samplerParam,
		},
	}

	closer, err := cfg.InitGlobalTracer(serviceName, config.Logger(jaeger.StdLogger))
	if err != nil {
		return nil, err
	}

	return &tracingService{closer: closer}, nil
}

// RegisterFlags registers the flags used by the tracing service.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgTracingEnabled, true, "Enable tracing")
		cmd.Flags().Duration(cfgTracingReporterFlushInterval, 1*time.Second, "How often the buffer is force-flushed, even if it's not full")
		cmd.Flags().String(cfgTracingReporterLocalAgentHostPort, "localhost:6831", "Send spans to jaeger-agent at this address")
		cmd.Flags().Float64(cfgTracingSamplerParam, 0.001, "Probability for probabilistic sampler")
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
