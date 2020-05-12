// Package metrics implements a prometheus metrics service.
package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/service"
	"github.com/oasislabs/oasis-core/go/common/version"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
)

const (
	CfgMetricsMode     = "metrics.mode"
	CfgMetricsAddr     = "metrics.address"
	CfgMetricsLabels   = "metrics.labels"
	CfgMetricsJobName  = "metrics.job_name"
	CfgMetricsInterval = "metrics.interval"

	MetricUp = "oasis_up"

	MetricsJobTestRunner = "oasis-test-runner"

	MetricsLabelGitBranch       = "git_branch"
	MetricsLabelInstance        = "instance"
	MetricsLabelRun             = "run"
	MetricsLabelSoftwareVersion = "software_version"
	MetricsLabelTest            = "test"

	MetricsModeNone = "none"
	MetricsModePull = "pull"
	MetricsModePush = "push"
)

// Flags has the flags used by the metrics service.
var (
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	UpGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricUp,
			Help: "Is oasis-test-runner or oasis-node active",
		},
	)
)

type stubService struct {
	service.BaseBackgroundService

	rsvc *resourceService
}

func (s *stubService) Start() error {
	if err := s.rsvc.Start(); err != nil {
		return err
	}

	return nil
}

func (s *stubService) Stop() {}

func (s *stubService) Cleanup() {}

func newStubService() (service.BackgroundService, error) {
	svc := *service.NewBaseBackgroundService("metrics")

	return &stubService{
		BaseBackgroundService: svc,
		rsvc:                  newResourceService(viper.GetDuration(CfgMetricsInterval)),
	}, nil
}

type pullService struct {
	service.BaseBackgroundService

	ln net.Listener
	s  *http.Server

	ctx   context.Context
	errCh chan error

	rsvc *resourceService
}

func (s *pullService) Start() error {
	if err := s.rsvc.Start(); err != nil {
		return err
	}

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
	addr := viper.GetString(CfgMetricsAddr)

	svc := *service.NewBaseBackgroundService("metrics")

	svc.Logger.Debug("Metrics Server Params",
		"mode", MetricsModePull,
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
		rsvc:                  newResourceService(viper.GetDuration(CfgMetricsInterval)),
	}, nil
}

type pushService struct {
	service.BaseBackgroundService

	pusher   *push.Pusher
	interval time.Duration

	rsvc *resourceService
}

func (s *pushService) Start() error {
	if err := s.rsvc.Start(); err != nil {
		return err
	}

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
			return
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
	addr := viper.GetString(CfgMetricsAddr)
	jobName := viper.GetString(CfgMetricsJobName)
	labels := viper.GetStringMapString(CfgMetricsLabels)
	interval := viper.GetDuration(CfgMetricsInterval)

	if jobName == "" {
		return nil, fmt.Errorf("metrics: %s required for push mode", CfgMetricsJobName)
	}
	if labels["instance"] == "" {
		return nil, fmt.Errorf("metrics: at least 'instance' key should be set for %s. Provided labels: %v", CfgMetricsLabels, labels)
	}

	svc := *service.NewBaseBackgroundService("metrics")

	svc.Logger.Debug("Metrics Server Params",
		"mode", MetricsModePush,
		"addr", addr,
		"job_name", jobName,
		"labels", labels,
		"push_interval", interval,
	)

	pusher := push.New(addr, jobName)
	for k, v := range labels {
		pusher = pusher.Grouping(k, v)
	}

	return &pushService{
		BaseBackgroundService: svc,
		pusher:                pusher,
		interval:              interval,
		rsvc:                  newResourceService(viper.GetDuration(CfgMetricsInterval)),
	}, nil
}

// New constructs a new metrics service.
func New(ctx context.Context) (service.BackgroundService, error) {
	mode := viper.GetString(CfgMetricsMode)
	switch strings.ToLower(mode) {
	case MetricsModeNone:
		return newStubService()
	case MetricsModePull:
		return newPullService(ctx)
	case MetricsModePush:
		return newPushService()
	default:
		return nil, fmt.Errorf("metrics: unsupported mode: '%v'", mode)
	}
}

// EscapeLabelCharacters replaces invalid prometheus label name characters with "_".
func EscapeLabelCharacters(l string) string {
	return strings.Replace(l, ".", "_", -1)
}

// GetDefaultPushLabels generates standard Prometheus push labels based on test current test instance info.
func GetDefaultPushLabels(ti *env.TestInstanceInfo) map[string]string {
	labels := map[string]string{
		MetricsLabelInstance:        ti.Instance,
		MetricsLabelRun:             strconv.Itoa(ti.Run),
		MetricsLabelTest:            ti.Test,
		MetricsLabelSoftwareVersion: version.SoftwareVersion,
	}
	if version.GitBranch != "" {
		labels[MetricsLabelGitBranch] = version.GitBranch
	}
	// Populate it with test-provided parameters.
	if ti.ParameterSet != nil {
		ti.ParameterSet.VisitAll(func(f *flag.Flag) {
			labels[EscapeLabelCharacters(f.Name)] = f.Value.String()
		})
		// Override any labels passed to oasis-test-runner via CLI.
		for k, v := range viper.GetStringMapString(CfgMetricsLabels) {
			labels[k] = v
		}

		// Remove empty label values - workaround for
		// https://github.com/prometheus/pushgateway/issues/344
		var emptyKeys []string
		for k, v := range labels {
			if v == "" {
				emptyKeys = append(emptyKeys, k)
			}
		}
		for _, k := range emptyKeys {
			delete(labels, k)
		}
	}

	return labels
}

func init() {
	Flags.String(CfgMetricsMode, MetricsModeNone, "metrics mode: none, pull, push")
	Flags.String(CfgMetricsAddr, "127.0.0.1:3000", "metrics pull/push address")
	Flags.String(CfgMetricsJobName, "", "metrics push job name")
	Flags.StringToString(CfgMetricsLabels, map[string]string{}, "metrics push instance label")
	Flags.Duration(CfgMetricsInterval, 5*time.Second, "metrics push interval")

	_ = viper.BindPFlags(Flags)
}
