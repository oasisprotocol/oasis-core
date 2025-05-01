package service

import (
	"context"
)

// AsBlocking transforms a background service into a blocking service.
func AsBlocking(service BackgroundService) Service {
	return &blockingService{
		service: service,
	}
}

// blockingService adapts a background service to run as a blocking service.
type blockingService struct {
	service BackgroundService
}

// Serve starts the background service and blocks until it either completes
// or the provided context is canceled. If the context is canceled, the service
// is stopped manually.
func (w *blockingService) Serve(ctx context.Context) error {
	if err := w.service.Start(); err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		w.service.Stop()
		return ctx.Err()
	case <-w.service.Quit():
		return nil
	}
}
