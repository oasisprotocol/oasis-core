package metrics

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
)

const (
	MetricDiskUsageBytes   = "oasis_node_disk_usage_bytes"
	MetricDiskReadBytes    = "oasis_node_disk_read_bytes"
	MetricDiskWrittenBytes = "oasis_node_disk_written_bytes"
)

var (
	diskUsageGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricDiskUsageBytes,
			Help: "Size of datadir of the worker (bytes).",
		},
	)

	diskIOReadBytesGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricDiskReadBytes,
			Help: "Read data from block storage by the worker as reported by /proc/<PID>/io (bytes).",
		},
	)

	diskIOWrittenBytesGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: MetricDiskWrittenBytes,
			Help: "Written data from block storage by the worker as reported by /proc/<PID>/io (bytes)",
		},
	)

	diskCollectors  = []prometheus.Collector{diskUsageGauge, diskIOReadBytesGauge, diskIOWrittenBytesGauge}
	diskServiceOnce sync.Once
)

type diskCollector struct {
	dataDir string
	// TODO: Should we monitor I/O of children PIDs as well?
	pid int
}

func (d *diskCollector) Name() string {
	return "disk"
}

func (d *diskCollector) Update() error {
	// Compute disk usage of datadir.
	var duBytes int64
	err := filepath.Walk(d.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("disk usage metric: failed to access file %s: %w", path, err)
		}
		duBytes += info.Size()
		return nil
	})
	if err != nil {
		return fmt.Errorf("disk usage metric: failed to walk directory %s: %w", d.dataDir, err)
	}
	diskUsageGauge.Set(float64(duBytes))

	// Obtain process I/O info.
	proc, err := procfs.NewProc(d.pid)
	if err != nil {
		return fmt.Errorf("disk I/O metric: failed to obtain proc object for PID %d: %w", d.pid, err)
	}
	procIO, err := proc.IO()
	if err != nil {
		return fmt.Errorf("disk I/O metric: failed to obtain procIO object %d: %w", d.pid, err)
	}

	diskIOWrittenBytesGauge.Set(float64(procIO.ReadBytes))
	diskIOReadBytesGauge.Set(float64(procIO.WriteBytes))

	return nil
}

// NewDiskService constructs a new disk usage and I/O service.
//
// This service will regularly compute the size of datadir folder and read I/O
// info of the process.
func NewDiskService() ResourceCollector {
	ds := &diskCollector{
		dataDir: common.DataDir(),
		pid:     os.Getpid(),
	}

	// Disk metrics are singletons per process. Ensure to register them only once.
	diskServiceOnce.Do(func() {
		prometheus.MustRegister(diskCollectors...)
	})

	return ds
}
