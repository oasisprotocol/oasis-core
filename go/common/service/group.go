package service

import (
	"context"
	"fmt"

	"golang.org/x/sync/errgroup"
)

// Group is responsible for concurrently starting a group of services.
type Group struct {
	services []Service
}

// NewGroup creates a new service group with the given list of services.
func NewGroup(services ...Service) *Group {
	return &Group{
		services: services,
	}
}

// Add appends one or more services to the group.
func (g *Group) Add(services ...Service) {
	g.services = append(g.services, services...)
}

// Serve starts all services concurrently and blocks until they all complete,
// one returns an error, or the context is canceled.
func (g *Group) Serve(ctx context.Context) error {
	group, ctx := errgroup.WithContext(ctx)

	for _, s := range g.services {
		group.Go(func() error {
			if err := s.Serve(ctx); err != nil {
				if ns, ok := s.(NamedService); ok {
					return fmt.Errorf("%s stopped: %w", ns.Name(), err)
				}
				return fmt.Errorf("service stopped: %w", err)
			}
			return nil
		})
	}

	return group.Wait()
}
