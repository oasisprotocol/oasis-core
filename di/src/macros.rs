//! Convenience macros.

// Re-export clap for use in macros.
#[doc(hidden)]
#[cfg(all(feature = "cli", not(target_env = "sgx")))]
pub mod clap {
    pub use clap::*;
}

/// Define an injectable component.
///
/// # Examples
///
/// Constructor without dependencies:
/// ```ignore
/// trait Backend { /* ... */ }
///
/// struct FooBackend;
/// impl FooBackend {
///     pub fn new() -> Self { /* ... */ }
/// }
///
/// create_component!(foo, "backend", FooBackend, Backend, []);
/// ```
///
/// Constructor with only injectable dependencies:
/// ```ignore
/// trait Backend { /* ... */ }
///
/// struct FooBackend;
/// impl FooBackend {
///     pub fn new(bar: Arc<Bar>) -> Self { /* ... */ }
/// }
///
/// create_component!(foo, "backend", FooBackend, Backend, [Bar]);
/// ```
///
/// Custom factory:
/// ```ignore
/// create_component!(
///     foo,
///     "backend",
///     FooBackend,
///     Backend,
///     (|container: &mut Container| -> Result<Box<Any>> {
///         let instance: Box<Backend> = Box::new(FooBackend::new());
///         Ok(Box::new(instance))
///     })
/// );
/// ```
///
/// Custom factrory with command-line arguments (requires `cli` feature):
/// ```ignore
/// create_component!(
///     foo,
///     "backend",
///     FooBackend,
///     Backend,
///     (|container: &mut Container| -> Result<Box<Any>> {
///         let args = container.get_arguments().unwrap();
///         let arg = args.value_of("dummy-arg").unwrap();
///
///         let instance: Box<Backend> = Box::new(FooBackend::new(arg));
///         Ok(Box::new(instance))
///     }),
///     [
///         Arg::with_name("dummy-arg")
///             .long("dummy-arg")
///             .help("Dummy argument")
///             .takes_value(true)
///             .default_value("boo")
///     ]
/// );
/// ```
#[macro_export]
macro_rules! create_component {
    (
        @factory
        $name:ident,
        $group:expr,
        $component:ident,
        $trait:ident,
        [ $( $dependency:ident ),*]
    ) => {
        #[allow(unused_variables)]
        fn build(&self, container: &mut Container) -> Result<Box<Any>> {
            let instance: Box<$trait> = Box::new($component::new(
                $( container.inject::<super::$dependency>()? ),*
            ));
            Ok(Box::new(instance))
        }
    };

    (
        @factory
        $name:ident,
        $group:expr,
        $component:ident,
        $trait:ident,
        $factory:expr
    ) => {
        #[allow(unused_variables)]
        fn build(&self, container: &mut Container) -> Result<Box<Any>> {
            $factory(container)
        }
    };

    (
        @factory
        $name:ident,
        $group:expr,
        $component:ident,
        $trait:ident,
        $factory:expr,
        [ $( $arg:expr ),* ]
    ) => {
        #[allow(unused_variables)]
        fn build(&self, container: &mut Container) -> Result<Box<Any>> {
            $factory(container)
        }

        fn get_arguments(&self) -> Vec<$crate::macros::clap::Arg<'static, 'static>> {
            #[allow(unused_imports)]
            use $crate::macros::clap::Arg;

            vec![$( $arg ),*]
        }
    };

    ($name:ident, $group:expr, $component:ident, $trait:ident, $( $args:tt ),+ ) => {
        #[doc(hidden)]
        pub mod $name {
            #[allow(unused_imports)]
            use ::std::any::Any;
            #[allow(unused_imports)]
            use ::std::sync::Arc;

            #[allow(unused_imports)]
            use $crate::di::*;
            #[allow(unused_imports)]
            use $crate::macros::*;
            use $crate::error::Result;

            use super::*;

            pub struct Factory;
            impl ComponentFactory for Factory {
                fn new() -> Self {
                    Factory
                }

                fn get_name(&self) -> &'static str {
                    stringify!($name)
                }

                fn get_group(&self) -> &'static str {
                    $group
                }

                create_component!(
                    @factory
                    $name,
                    $group,
                    $component,
                    $trait,
                    $( $args ),+
                );
            }

            impl $crate::Component for $component {
                type Factory = Factory;

                fn register(registry: &mut $crate::KnownComponents) {
                    registry.register::<$component, $trait>();
                }
            }
        }
    }
}
