package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/service"
)

const (
	cfgMetricsMode              = "metrics.mode"
	cfgMetricsAddr              = "metrics.address"
	cfgMetricsPushJobName       = "metrics.push.job-name"
	cfgMetricsPushInstanceLabel = "metrics.push.instance-label"
	cfgMetricsPushInterval      = "metrics.push.interval"

	metricsModePull = "pull"
	metricsModePush = "push"
)

var (
	metricsMode string
	metricsAddr string

	metricsPushJobName       string
	metricsPushInstanceLabel string
	metricsPushInterval      time.Duration
)

type metricsPullService struct {
	service.BaseBackgroundService

	ln net.Listener
	s  *http.Server

	errCh chan error
}

func (s *metricsPullService) Start() error {
	go func() {
		if err := s.s.Serve(s.ln); err != nil {
			s.BaseBackgroundService.Stop()
			s.errCh <- err
		}
	}()
	return nil
}

func (s *metricsPullService) Stop() {
	if s.s != nil {
		select {
		case err := <-s.errCh:
			if err != nil {
				s.Logger.Error("metrics terminated uncleanly",
					"err", err,
				)
			}
		default:
			_ = s.s.Shutdown(context.Background())
		}
		s.s = nil
	}
}

func (s *metricsPullService) Cleanup() {
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func newMetricsPullService(cmd *cobra.Command) (service.BackgroundService, error) {
	addr, _ := cmd.Flags().GetString(cfgMetricsAddr)

	svc := *service.NewBaseBackgroundService("metrics")

	svc.Logger.Debug("Metrics Server Params",
		"mode", metricsModePull,
		"addr", addr,
	)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &metricsPullService{
		BaseBackgroundService: svc,
		ln:                    ln,
		s:                     &http.Server{Handler: promhttp.Handler()},
		errCh:                 make(chan error),
	}, nil
}

type metricsPushService struct {
	service.BaseBackgroundService

	pusher   *push.Pusher
	interval time.Duration
}

func (s *metricsPushService) Start() error {
	s.pusher = s.pusher.Gatherer(prometheus.DefaultGatherer)

	go s.worker()
	return nil
}

func (s *metricsPushService) worker() {
	t := time.NewTicker(s.interval)
	defer t.Stop()

	for {
		select {
		case <-s.Quit():
			break
		case <-t.C:
		}

		if err := s.pusher.Push(); err != nil {
			s.Logger.Warn("Push: failed",
				"err", err,
			)
		}
	}
}

func newMetricsPushService(cmd *cobra.Command) (service.BackgroundService, error) {
	addr, _ := cmd.Flags().GetString(cfgMetricsAddr)
	jobName, _ := cmd.Flags().GetString(cfgMetricsPushJobName)
	instanceLabel, _ := cmd.Flags().GetString(cfgMetricsPushInstanceLabel)
	interval, _ := cmd.Flags().GetDuration(cfgMetricsPushInterval)

	if jobName == "" {
		return nil, fmt.Errorf("metrics: metrics.push.job-name required for push mode")
	}
	if instanceLabel == "" {
		return nil, fmt.Errorf("metrics: metrics.push.instance-label required for push mode")
	}

	svc := *service.NewBaseBackgroundService("metrics")

	svc.Logger.Debug("Metrics Server Params",
		"mode", metricsModePush,
		"addr", addr,
		"job_name", jobName,
		"instance_label", instanceLabel,
		"push_interval", interval,
	)

	return &metricsPushService{
		BaseBackgroundService: svc,
		pusher:                push.New(addr, jobName).Grouping("instance", instanceLabel),
		interval:              interval,
	}, nil
}

func newMetrics(cmd *cobra.Command) (service.BackgroundService, error) {
	mode, _ := cmd.Flags().GetString(cfgMetricsMode)
	switch strings.ToLower(mode) {
	case metricsModePull:
		return newMetricsPullService(cmd)
	case metricsModePush:
		return newMetricsPushService(cmd)
	default:
		return nil, fmt.Errorf("metrics: unsupported mode: '%v'", mode)
	}
}

func registerMetricsFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&metricsMode, cfgMetricsMode, metricsModePull, "metrics (prometheus) mode")
	cmd.Flags().StringVar(&metricsAddr, cfgMetricsAddr, "0.0.0.0:3000", "metrics pull/push address")
	cmd.Flags().StringVar(&metricsPushJobName, cfgMetricsPushJobName, "", "metrics push job name")
	cmd.Flags().StringVar(&metricsPushInstanceLabel, cfgMetricsPushInstanceLabel, "", "metrics push instance label")
	cmd.Flags().DurationVar(&metricsPushInterval, cfgMetricsPushInterval, 5*time.Second, "metrics push interval")

	for _, v := range []string{
		cfgMetricsMode,
		cfgMetricsAddr,
		cfgMetricsPushJobName,
		cfgMetricsPushInstanceLabel,
		cfgMetricsPushInterval,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
