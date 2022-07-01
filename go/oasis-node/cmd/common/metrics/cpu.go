package metrics

import (
	"fmt"
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

const (
	MetricCPUUTimeSeconds = "oasis_node_cpu_utime_seconds"
	MetricCPUSTimeSeconds = "oasis_node_cpu_stime_seconds"

	// ClockTicks is getconf CLK_TCK
	ClockTicks = 100
)

var (
	utimeGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricCPUUTimeSeconds,
			Help: "CPU user time spent by worker as reported by /proc/<PID>/stat (seconds).",
		},
	)

	stimeGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricCPUSTimeSeconds,
			Help: "CPU system time spent by worker as reported by /proc/<PID>/stat (seconds).",
		},
	)

	cpuCollectors  = []prometheus.Collector{utimeGauge, stimeGauge}
	cpuServiceOnce sync.Once
)

type cpuCollector struct {
	// TODO: Should we monitor memory of children PIDs as well?
	pid int
}

func (c *cpuCollector) Name() string {
	return "cpu"
}

func (c *cpuCollector) Update() error {
	// Obtain process CPU info.
	proc, err := procfs.NewProc(c.pid)
	if err != nil {
		return fmt.Errorf("CPU metric: failed to obtain proc object for PID %d: %w", c.pid, err)
	}
	procStat, err := proc.Stat()
	if err != nil {
		return fmt.Errorf("CPU metric: failed to obtain procStat object %d: %w", c.pid, err)
	}

	utimeGauge.Set(float64(procStat.UTime) / float64(ClockTicks))
	stimeGauge.Set(float64(procStat.STime) / float64(ClockTicks))

	return nil
}

// NewCPUCollector constructs a new CPU usage collector.
//
// This service will regularly read CPU spent time info from process Stat file.
func NewCPUCollector() ResourceCollector {
	cs := &cpuCollector{
		pid: os.Getpid(),
	}

	// CPU metrics are singletons per process. Ensure to register them only once.
	cpuServiceOnce.Do(func() {
		prometheus.MustRegister(cpuCollectors...)
	})

	return cs
}
