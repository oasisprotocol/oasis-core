//! Tracing helpers.
use io_context::Context;

const TRACING_SPAN_CONTEXT_KEY: &'static str = "EKIDEN_TRACING_SPAN_CONTEXT";

/// Add a tracing span context to the provided `Context`.
pub fn add_span_context(ctx: &mut Context, span_context: Vec<u8>) {
    ctx.add_value(TRACING_SPAN_CONTEXT_KEY, span_context);
}

/// Retrieve a tracing span context from the provided `Context`.
pub fn get_span_context(ctx: &Context) -> Option<&Vec<u8>> {
    ctx.get_value(TRACING_SPAN_CONTEXT_KEY)
}
