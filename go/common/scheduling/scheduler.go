// Package scheduling provides tools for scheduling tasks.
package scheduling

import (
	"context"
)

// Scheduler is an interface for scheduling tasks.
type Scheduler interface {
	// AddTask adds given task to the scheduler.
	AddTask(name string, fn func(ctx context.Context) error)

	// Start starts executing tasks in the background. If the scheduler is already running, this is
	// a noop operation.
	Start()

	// Stop stops executing tasks. If the scheduler is not running, this is a noop operation.
	Stop()
}
