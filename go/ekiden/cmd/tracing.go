package cmd

import (
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/uber/jaeger-client-go"
	"github.com/uber/jaeger-client-go/config"
)

const (
	cfgTracingEnabled                    = "tracing.enabled"
	cfgTracingReporterFlushInterval      = "tracing.reporter.flush-interval"
	cfgTracingReporterLocalAgentHostPort = "tracing.reporter.agent-addr"
	cfgTracingSamplerParam               = "tracing.sampler.param"
)

var (
	tracingEnabled                    bool
	tracingReporterFlushInterval      time.Duration
	tracingReporterLocalAgentHostPort string
	tracingSamplerParam               float64
)

func initTracing(cmd *cobra.Command, serviceName string) (io.Closer, error) {
	enabled, _ := cmd.Flags().GetBool(cfgTracingEnabled)
	reporterFlushInterval, _ := cmd.Flags().GetDuration(cfgTracingReporterFlushInterval)
	reporterLocalAgentHostPort, _ := cmd.Flags().GetString(cfgTracingReporterLocalAgentHostPort)
	samplerParam, _ := cmd.Flags().GetFloat64(cfgTracingSamplerParam)

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

	return cfg.InitGlobalTracer(serviceName, config.Logger(jaeger.StdLogger))
}

func registerTracingFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&tracingEnabled, cfgTracingEnabled, true, "Enable tracing")
	cmd.Flags().DurationVar(&tracingReporterFlushInterval, cfgTracingReporterFlushInterval, 1*time.Second, "How often the buffer is force-flushed, even if it's not full")
	cmd.Flags().StringVar(&tracingReporterLocalAgentHostPort, cfgTracingReporterLocalAgentHostPort, "localhost:6831", "Send spans to jaeger-agent at this address")
	cmd.Flags().Float64Var(&tracingSamplerParam, cfgTracingSamplerParam, 0.001, "Probability for probabilistic sampler")

	for _, v := range []string{
		cfgTracingEnabled,
		cfgTracingReporterFlushInterval,
		cfgTracingReporterLocalAgentHostPort,
		cfgTracingSamplerParam,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
