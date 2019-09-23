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
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/service"
)

const (
	cfgMetricsMode              = "metrics.mode"
	cfgMetricsAddr              = "metrics.address"
	cfgMetricsPushJobName       = "metrics.push.job_name"
	cfgMetricsPushInstanceLabel = "metrics.push.instance_label"
	cfgMetricsPushInterval      = "metrics.push.interval"

	metricsModeNone = "none"
	metricsModePull = "pull"
	metricsModePush = "push"
)

// Flags has the flags used by the metrics service.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// ServiceConfig contains the configuration parameters for metrics.
type ServiceConfig struct {
	// Mode is the service mode ("none", "pull", "push").
	Mode string
	// Address is the address of the push server.
	Address string
	// JobName is the name of the job for which metrics are collected.
	JobName string
	// InstanceLabel is the instance label of the job being collected for.
	InstanceLabel string
	// Interval defined the push interval for metrics collection.
	Interval time.Duration
}

// GetServiceConfig gets the metrics configuration parameter struct.
func GetServiceConfig() *ServiceConfig {
	return &ServiceConfig{
		Mode:          viper.GetString(cfgMetricsMode),
		Address:       viper.GetString(cfgMetricsAddr),
		JobName:       viper.GetString(cfgMetricsPushJobName),
		InstanceLabel: viper.GetString(cfgMetricsPushInstanceLabel),
		Interval:      viper.GetDuration(cfgMetricsPushInterval),
	}
}

type stubService struct {
	service.BaseBackgroundService
}

func (s *stubService) Start() error {
	return nil
}

func (s *stubService) Stop() {}

func (s *stubService) Cleanup() {}

func newStubService() (service.BackgroundService, error) {
	svc := *service.NewBaseBackgroundService("metrics")

	return &stubService{
		BaseBackgroundService: svc,
	}, nil
}

type pullService struct {
	service.BaseBackgroundService

	ln net.Listener
	s  *http.Server

	ctx   context.Context
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
			_ = s.s.Shutdown(s.ctx)
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

func newPullService(ctx context.Context) (service.BackgroundService, error) {
	addr := viper.GetString(cfgMetricsAddr)

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
		ctx:                   ctx,
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

func newPushService() (service.BackgroundService, error) {
	addr := viper.GetString(cfgMetricsAddr)
	jobName := viper.GetString(cfgMetricsPushJobName)
	instanceLabel := viper.GetString(cfgMetricsPushInstanceLabel)
	interval := viper.GetDuration(cfgMetricsPushInterval)

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
func New(ctx context.Context) (service.BackgroundService, error) {
	mode := viper.GetString(cfgMetricsMode)
	switch strings.ToLower(mode) {
	case metricsModeNone:
		return newStubService()
	case metricsModePull:
		return newPullService(ctx)
	case metricsModePush:
		return newPushService()
	default:
		return nil, fmt.Errorf("metrics: unsupported mode: '%v'", mode)
	}
}

func init() {
	Flags.String(cfgMetricsMode, metricsModeNone, "metrics (prometheus) mode")
	Flags.String(cfgMetricsAddr, "127.0.0.1:3000", "metrics pull/push address")
	Flags.String(cfgMetricsPushJobName, "", "metrics push job name")
	Flags.String(cfgMetricsPushInstanceLabel, "", "metrics push instance label")
	Flags.Duration(cfgMetricsPushInterval, 5*time.Second, "metrics push interval")

	_ = viper.BindPFlags(Flags)
}
