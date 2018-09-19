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
	cfgTracingDisabled              = "tracing.disabled"
	cfgTracingReporterFlushInterval = "tracing.reporter.flush-interval"
	cfgTracingSamplerParam          = "tracing.sampler.param"
)

var (
	tracingDisabled              bool
	tracingReporterFlushInterval time.Duration
	tracingSamplerParam          float64
)

func initTracing(cmd *cobra.Command, serviceName string) (io.Closer, error) {
	disabled, _ := cmd.Flags().GetBool(cfgTracingDisabled)
	reporterFlushInterval, _ := cmd.Flags().GetDuration(cfgTracingReporterFlushInterval)
	samplerParam, _ := cmd.Flags().GetFloat64(cfgTracingSamplerParam)

	cfg := config.Configuration{
		Disabled: disabled,
		Reporter: &config.ReporterConfig{
			BufferFlushInterval: reporterFlushInterval,
		},
		Sampler: &config.SamplerConfig{
			Param: samplerParam,
		},
	}

	return cfg.InitGlobalTracer(serviceName, config.Logger(jaeger.StdLogger))
}

func registerTracingFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&tracingDisabled, cfgTracingDisabled, true, "Disable tracing")
	cmd.Flags().DurationVar(&tracingReporterFlushInterval, cfgTracingReporterFlushInterval, 1*time.Second, "How often the buffer is force-flushed, even if it's not full")
	cmd.Flags().Float64Var(&tracingSamplerParam, cfgTracingSamplerParam, 0.001, "Probability for probabilistic sampler")

	for _, v := range []string{
		cfgTracingDisabled,
		cfgTracingSamplerParam,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
