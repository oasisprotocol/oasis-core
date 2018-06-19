/// Macro for creating API definitions.
///
/// This is a meta-macro, which generates a new macro called `with_api` in its
/// place. The `with_api` macro can be used to invoke other macros while
/// passing the API as an argument to that macro. The position of the argument
/// containing the API definition is specified by using the special `api` token
/// in its place.
///
/// # Examples
///
/// For example, if you want to create enclave glue from the given API, and
/// have the `create_enclave_rpc` macro available, you can invoke it with this
/// concrete API by doing:
/// ```ignore
/// with_api! {
///     create_enclave_rpc!(api);
/// }
/// ```
///
/// # Limitations
///
/// Currently the `api` token can only appear as the last argument and there
/// can be at most five arguments to the inner macro.
#[macro_export]
macro_rules! rpc_api {
    (
        $($api: tt)*
    ) => {
        /// Invoke another macro passing the API as specified argument.
        ///
        /// # Examples
        ///
        /// For example, if you want to create enclave glue from the given API, and
        /// have the `create_enclave_rpc` macro available, you can invoke it with this
        /// concrete API by doing:
        /// ```
        /// with_api! {
        ///     create_enclave_rpc!(api);
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
