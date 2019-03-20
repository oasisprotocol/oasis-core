// Package tracing complements the opentracing go package.
package tracing

import (
	"bytes"
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

// SpanContextToBinary marshals the given SpanContext to a binary format using
// the global tracer.
// Returns either the in-memory bytes array or an error.
func SpanContextToBinary(sc opentracing.SpanContext) ([]byte, error) {
	scBinary := []byte{}
	scBuffer := new(bytes.Buffer)

	err := opentracing.GlobalTracer().Inject(sc, opentracing.Binary, scBuffer)
	if err != nil {
		return nil, err
	}

	if scBuffer.Bytes() != nil {
		scBinary = scBuffer.Bytes()
	}

	return scBinary, err
}

// SpanContextFromBinary unmarshals the given byte array containing the
// SpanContext in binary format.
// Returns a new SpanContext instance using the global tracer.
func SpanContextFromBinary(scBinary []byte) (opentracing.SpanContext, error) {
	var scReader = bytes.NewReader(scBinary)
	sc, err := opentracing.GlobalTracer().Extract(opentracing.Binary, scReader)

	return sc, err
}
