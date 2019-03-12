/// Macro for creating runtime API definitions.
///
/// This is a meta-macro, which generates a new macro called `with_api` in its
/// place. The `with_api` macro can be used to invoke other macros while
/// passing the API as an argument to that macro. The position of the argument
/// containing the API definition is specified by using the special `api` token
/// in its place.
///
/// # Examples
///
/// For example, if you want to register runtime methods with the dispatcher
/// based on the given API, and have the `register_runtime_txn_methods` macro
/// available, you can invoke it with this concrete API by doing:
/// ```rust,ignore
/// with_api! {
///     register_runtime_txn_methods!(txn_dispatcher, api);
/// }
/// ```
///
/// # Limitations
///
/// Currently the `api` token can only appear as the last argument and there
/// can be at most five arguments to the inner macro.
#[macro_export]
macro_rules! runtime_api {
    (
        $($api: tt)*
    ) => {
        /// Invoke another macro passing the API as specified argument.
        ///
        /// # Examples
        ///
        /// For example, if you want to register runtime methods with the dispatcher
        /// based on the given API, and have the `create_runtime` macro available, you
        /// can invoke it with this concrete API by doing:
        /// ```rust,ignore
        /// with_api! {
        ///     create_runtime!(api);
        /// }
        /// ```
        #[macro_export]
        macro_rules! with_api {
            // TODO: Repetition in nested macros currently not possible (see the Rust language
            //       issue: https://github.com/rust-lang/rust/issues/35853). This is also the
            //       reason why "api" can only be passed as the last argument.
            ( $macro_name:ident ! ( api ) ; ) => {
                $macro_name!( $($api)* );
            };

            ( $macro_name:ident ! ( $arg0:tt, api ) ; ) => {
                $macro_name!( $arg0, $($api)* );
            };

            ( $macro_name:ident ! ( $arg0:tt, $arg1:tt, api ) ; ) => {
                $macro_name!( $arg0, $arg1, $($api)* );
            };

            ( $macro_name:ident ! ( $arg0:tt, $arg1:tt, $arg2:tt, api ) ; ) => {
                $macro_name!( $arg0, $arg1, $arg2, $($api)* );
            };

            ( $macro_name:ident ! ( $arg0:tt, $arg1:tt, $arg2:tt, $arg3:tt, api ) ; ) => {
                $macro_name!( $arg0, $arg1, $arg2, $arg3, $($api)* );
            };
        }
    }
}

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

/// Move custom runtime context from a dispatcher context.
///
/// # Examples
///
/// ```rust,ignore
/// fn end_batch(&self, ctx: TxnContext) -> Fallible<()> {
///     let rctx = runtime_context_move!(ctx, MyContext);
///
///     // ...
/// }
/// ```
#[macro_export]
macro_rules! runtime_context_move {
    ($ctx:ident, $type:ty) => {
        $ctx.runtime
            .downcast::<$type>()
            .expect("invalid runtime context")
    };
}
