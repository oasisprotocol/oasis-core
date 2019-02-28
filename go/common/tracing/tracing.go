// Package tracing complements the opentracing go package.
package tracing

import (
	"context"

	"github.com/opentracing/opentracing-go"
)

// StartSpanWithContext creates a new span and returns a context containing it.
// In contrast to opentracing.StartSpanFromContext(), this function does not
// take existing span from `ctx` as a ChildOfRef.
func StartSpanWithContext(ctx context.Context, operationName string, opts ...opentracing.StartSpanOption) (opentracing.Span, context.Context) {
	span := opentracing.StartSpan(operationName, opts...)
	return span, opentracing.ContextWithSpan(ctx, span)
}
