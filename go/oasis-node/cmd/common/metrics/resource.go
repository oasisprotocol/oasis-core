package metrics

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/service"
)

// ResourceCollector is interface for monitoring resources (cpu, mem, disk, net).
type ResourceCollector interface {
	// Name returns the resource collector name.
	Name() string

	// Update updates corresponding resource metrics.
	Update() error
}

// resourceService regularly updates and collects a number of resources. Update
// interval is passed when calling newResourceService(). This usually equals
// the frequency of reporting the metrics to Prometheus (--metrics.interval).
type resourceService struct {
	service.BaseBackgroundService

	interval   time.Duration
	collectors []ResourceCollector
}

func (rs *resourceService) Start() error {
	go rs.worker()
	return nil
}

func (rs *resourceService) worker() {
	t := time.NewTicker(rs.interval)
	defer t.Stop()

	for {
		select {
		case <-rs.Quit():
			return
		case <-t.C:
		}

		for _, r := range rs.collectors {
			if err := r.Update(); err != nil {
				rs.Logger.Warn("failed to update resource collector", "collector", r.Name(), "err", err)
			}
		}
	}
}

func newResourceService(interval time.Duration) *resourceService {
	rs := &resourceService{
		BaseBackgroundService: *service.NewBaseBackgroundService("resources_watcher"),
		interval:              interval,
		collectors: []ResourceCollector{
			NewDiskService(),
			NewMemService(),
			NewCPUCollector(),
			NewNetService(),
		},
	}

	return rs
}
