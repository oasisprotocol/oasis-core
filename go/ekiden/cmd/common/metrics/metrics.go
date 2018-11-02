// Package metrics implements a prometheus metrics service.
package metrics

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
	cfgMetricsPushJobName       = "metrics.push.job_name"
	cfgMetricsPushInstanceLabel = "metrics.push.instance_label"
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

type pullService struct {
	service.BaseBackgroundService

	ln net.Listener
	s  *http.Server

	errCh chan error
}

func (s *pullService) Start() error {
	go func() {
		if err := s.s.Serve(s.ln); err != nil {
			s.BaseBackgroundService.Stop()
			s.errCh <- err
		}
	}()
	return nil
}

func (s *pullService) Stop() {
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

func (s *pullService) Cleanup() {
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func newPullService(cmd *cobra.Command) (service.BackgroundService, error) {
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

	return &pullService{
		BaseBackgroundService: svc,
		ln:                    ln,
		s:                     &http.Server{Handler: promhttp.Handler()},
		errCh:                 make(chan error),
	}, nil
}

type pushService struct {
	service.BaseBackgroundService

	pusher   *push.Pusher
	interval time.Duration
}

func (s *pushService) Start() error {
	s.pusher = s.pusher.Gatherer(prometheus.DefaultGatherer)

	go s.worker()
	return nil
}

func (s *pushService) worker() {
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

func newPushService(cmd *cobra.Command) (service.BackgroundService, error) {
	addr, _ := cmd.Flags().GetString(cfgMetricsAddr)
	jobName, _ := cmd.Flags().GetString(cfgMetricsPushJobName)
	instanceLabel, _ := cmd.Flags().GetString(cfgMetricsPushInstanceLabel)
	interval, _ := cmd.Flags().GetDuration(cfgMetricsPushInterval)

	if jobName == "" {
		return nil, fmt.Errorf("metrics: metrics.push.job_name required for push mode")
	}
	if instanceLabel == "" {
		return nil, fmt.Errorf("metrics: metrics.push.instance_label required for push mode")
	}

	svc := *service.NewBaseBackgroundService("metrics")

	svc.Logger.Debug("Metrics Server Params",
		"mode", metricsModePush,
		"addr", addr,
		"job_name", jobName,
		"instance_label", instanceLabel,
		"push_interval", interval,
	)

	return &pushService{
		BaseBackgroundService: svc,
		pusher:                push.New(addr, jobName).Grouping("instance", instanceLabel),
		interval:              interval,
	}, nil
}

// New constructs a new metrics service.
func New(cmd *cobra.Command) (service.BackgroundService, error) {
	mode, _ := cmd.Flags().GetString(cfgMetricsMode)
	switch strings.ToLower(mode) {
	case metricsModePull:
		return newPullService(cmd)
	case metricsModePush:
		return newPushService(cmd)
	default:
		return nil, fmt.Errorf("metrics: unsupported mode: '%v'", mode)
	}
}

// RegisterFlags registers the flags used by the metrics service.
func RegisterFlags(cmd *cobra.Command) {
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
