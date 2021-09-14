/// Extract custom runtime context from a dispatcher context.
///
/// # Examples
///
/// ```rust,ignore
/// fn my_call(args: &bool, ctx: &mut TxnContext) -> Fallible<()> {
///     let rctx = runtime_context!(ctx, MyContext);
///
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! runtime_context {
    ($ctx:ident, $type:ty) => {
        $ctx.runtime
            .downcast_mut::<$type>()
            .expect("invalid runtime context")
    };
}
