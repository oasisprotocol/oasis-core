// Package background implements utilities for managing background
// services.
package background

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/service"
)

// ServiceManager manages a group of background services.
type ServiceManager struct {
	Ctx      context.Context
	cancelFn context.CancelFunc
	logger   *logging.Logger

	services []service.BackgroundService
	termCh   chan service.BackgroundService
	termSvc  service.BackgroundService

	stopCh chan struct{}
}

// Register registers a background service.
func (m *ServiceManager) Register(srv service.BackgroundService) {
	m.services = append(m.services, srv)
	go func() {
		<-srv.Quit()
		select {
		case m.termCh <- srv:
		default:
		}
	}()
}

// RegisterCleanupOnly registers a cleanup only background service.
func (m *ServiceManager) RegisterCleanupOnly(svc service.CleanupAble, name string) {
	m.services = append(m.services, service.NewCleanupOnlyService(svc, name))
}

// Wait waits for interruption via Stop, SIGINT, SIGTERM, or any of
// the registered services to terminate, and stops all services.
func (m *ServiceManager) Wait() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-m.stopCh:
		m.logger.Info("programatic termination requested")
	case m.termSvc = <-m.termCh:
		m.logger.Info("background task terminated, propagating")
	case <-sigCh:
		m.logger.Info("user requested termination")
	}

	// Cancel the context before stopping the services.
	m.cancelFn()

	for _, svc := range m.services {
		if svc != m.termSvc {
			svc.Stop()
		}
	}
}

// Stop stops all services.
func (m *ServiceManager) Stop() {
	close(m.stopCh)
	m.cancelFn()
}

// Cleanup cleans up after all registered services.
func (m *ServiceManager) Cleanup() {
	m.logger.Debug("begining cleanup")

	for _, svc := range m.services {
		m.logger.Debug("cleaning up",
			"svc", svc.Name(),
		)
		svc.Cleanup()
	}

	m.logger.Debug("finished cleanup")
}

// NewServiceManager creates a new ServiceManager with the provided logger.
func NewServiceManager(logger *logging.Logger) *ServiceManager {
	ctx, cancelFn := context.WithCancel(context.Background())

	return &ServiceManager{
		Ctx:      ctx,
		cancelFn: cancelFn,
		logger:   logger,
		termCh:   make(chan service.BackgroundService),
		stopCh:   make(chan struct{}),
	}
}
