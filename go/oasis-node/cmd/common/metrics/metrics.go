// Package metrics implements a prometheus metrics service.
package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/push"
	flag "github.com/spf13/pflag"

	"github.com/oasisprotocol/oasis-core/go/common/service"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

const (
	MetricUp = "oasis_up"

	MetricsJobTestRunner = "oasis-test-runner"

	MetricsLabelGitBranch       = "git_branch"
	MetricsLabelInstance        = "instance"
	MetricsLabelRun             = "run"
	MetricsLabelSoftwareVersion = "software_version"
	MetricsLabelScenario        = "scenario"

	MetricsModeNone = "none"
	MetricsModePull = "pull"
	MetricsModePush = "push"
)

var (
	UpGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricUp,
			Help: "Is oasis-test-runner active for specific scenario.",
		},
	)

	invalidLabelCharactersRegexp = regexp.MustCompile(`[^a-zA-Z0-9_]`)
)

func newStubService() (service.BackgroundService, error) {
	return service.NewBaseBackgroundService("metrics"), nil
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
			s.errCh <- err
		}

		<-s.rsvc.Quit()
		s.BaseBackgroundService.Stop()
	}()
	return nil
}

func (s *pullService) Stop() {
	s.rsvc.Stop()

	if s.s != nil {
		select {
		case err := <-s.errCh:
			if err != nil {
				s.Logger.Error("metrics terminated uncleanly",
					"err", err,
				)
			}
		default:
			_ = s.s.Close()
		}
		s.s = nil
	}
}

func (s *pullService) Cleanup() {
	s.rsvc.Cleanup()

	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func newPullService(ctx context.Context) (service.BackgroundService, error) {
	addr := config.GlobalConfig.Metrics.Address

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
		s:                     &http.Server{Handler: promhttp.Handler(), ReadTimeout: 5 * time.Second},
		errCh:                 make(chan error),
		rsvc:                  newResourceService(config.GlobalConfig.Metrics.Interval),
	}, nil
}

type pushService struct {
	service.BaseBackgroundService

	pusher *push.Pusher

	addr     string
	jobName  string
	labels   map[string]string
	interval time.Duration

	rsvc *resourceService

	stopCh chan struct{}
	quitCh chan struct{}
}

func (s *pushService) Start() error {
	if err := s.rsvc.Start(); err != nil {
		return err
	}

	s.pusher = s.pusher.Gatherer(prometheus.DefaultGatherer)

	go s.worker()
	return nil
}

func (s *pushService) Stop() {
	close(s.stopCh)
}

func (s *pushService) Quit() <-chan struct{} {
	return s.quitCh
}

func (s *pushService) Cleanup() {
	s.rsvc.Cleanup()
}

func (s *pushService) worker() {
	defer func() {
		s.rsvc.Stop()
		<-s.rsvc.Quit()
		close(s.quitCh)
	}()

	t := time.NewTicker(s.interval)
	defer t.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
		}

		if err := s.pusher.Push(); err != nil {
			s.Logger.Warn("Push: failed",
				"err", err,
			)

			// Once a pusher fails to push, it fails forever,
			// so re-create the pusher.
			s.initPusher(true)
		}
	}
}

func (s *pushService) initPusher(isReinit bool) {
	if !isReinit {
		s.Logger.Debug("initializing metrics push service",
			"mode", MetricsModePush,
			"addr", s.addr,
			"job_name", s.jobName,
			"labels", s.labels,
			"push_interval", s.interval,
		)
	}

	pusher := push.New(s.addr, s.jobName)
	for k, v := range s.labels {
		pusher = pusher.Grouping(k, v)
	}

	if isReinit {
		pusher = pusher.Gatherer(prometheus.DefaultGatherer)
	}

	s.pusher = pusher
}

func newPushService() (service.BackgroundService, error) {
	svc := &pushService{
		BaseBackgroundService: *service.NewBaseBackgroundService("metrics"),
		addr:                  config.GlobalConfig.Metrics.Address,
		jobName:               config.GlobalConfig.Metrics.JobName,
		labels:                config.GlobalConfig.Metrics.Labels,
		interval:              config.GlobalConfig.Metrics.Interval,
		rsvc:                  newResourceService(config.GlobalConfig.Metrics.Interval),
		stopCh:                make(chan struct{}),
		quitCh:                make(chan struct{}),
	}

	if svc.jobName == "" {
		return nil, fmt.Errorf("metrics: job_name required for push mode")
	}
	if svc.labels["instance"] == "" {
		return nil, fmt.Errorf("metrics: at least 'instance' key should be set for labels. Provided labels: %v", svc.labels)
	}

	svc.initPusher(false)

	return svc, nil
}

// New constructs a new metrics service.
func New(ctx context.Context) (service.BackgroundService, error) {
	mode := strings.ToLower(config.GlobalConfig.Metrics.Mode)
	switch mode {
	case MetricsModeNone:
		return newStubService()
	case MetricsModePull:
		return newPullService(ctx)
	default:
		if mode == MetricsModePush && flags.DebugDontBlameOasis() {
			return newPushService()
		}
		return nil, fmt.Errorf("metrics: unsupported mode: '%v'", mode)
	}
}

// Enabled returns if metrics are enabled.
func Enabled() bool {
	return config.GlobalConfig.Metrics.Mode != MetricsModeNone
}

// EscapeLabelCharacters replaces invalid prometheus label name characters with "_".
func EscapeLabelCharacters(l string) string {
	return invalidLabelCharactersRegexp.ReplaceAllString(l, "_")
}

// GetDefaultPushLabels generates standard Prometheus push labels based on test current test instance info.
func GetDefaultPushLabels(ti *env.ScenarioInstanceInfo) map[string]string {
	labels := map[string]string{
		MetricsLabelInstance:        ti.Instance,
		MetricsLabelRun:             strconv.Itoa(ti.Run),
		MetricsLabelScenario:        ti.Scenario,
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
		for k, v := range config.GlobalConfig.Metrics.Labels {
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
