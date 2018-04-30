/// Define a database schema structure.
///
/// Each field in the defined structure is replaced by a descriptor for the given
/// field type. A [`ScalarDescriptor`] is generated for each scalar field and a
/// [`MapDescriptor`] is generated for each `Map<K, V>` field.
///
/// Any type that implements the [`Serialize`] and [`Deserialize`] traits can be
/// used in the schema struct as a value (either as a scalar field or in a map).
///
/// Any type that implements the [`Serialize`] trait can be used in the schema
/// struct as a key in mappings.
///
/// [`ScalarDescriptor`]: super::descriptor::ScalarDescriptor
/// [`MapDescriptor`]: super::descriptor::MapDescriptor
/// [`Serialize`]: serde::Serialize
/// [`Deserialize`]: serde::Deserialize
///
/// # Examples
///
/// ```ignore
/// database_schema! {
///     pub struct MySchema {
///         pub foo: String,
///         pub bar: u64,
///         pub mapping: Map<String, u64>,
///     }
/// }
/// ```
#[macro_export]
macro_rules! database_schema {
    () => {};

    // Entry point, parse struct(s).
    (
        $(
            pub struct $schema_name:ident {
                $($body:tt)*
            }
        )*
    ) => {
        $(
            database_schema!(@parse_body($schema_name) -> ($($body)*));
        )*
    };

    // Internal pattern: parse map field.
    (
        @parse_body($($args:tt)*) -> (
            pub $field_name:ident : Map<$key_type:ty, $value_type:ty>,
            $($tail:tt)*
        )
    ) => {
        database_schema!(
            @parse_body(
                $($args)*,
                (
                    $field_name,
                    $crate::schema::descriptor::MapDescriptor<$key_type, $value_type>,
                    $crate::schema::descriptor::MapDescriptor::new
                )
            ) -> (
                $($tail)*
            )
        );
    };

    // Internal pattern: parse scalar field.
    (
        @parse_body($($args:tt)*) -> (
            pub $field_name:ident : $field_type:ty,
            $($tail:tt)*
        )
    ) => {
        database_schema!(
            @parse_body(
                $($args)*,
                (
                    $field_name,
                    $crate::schema::descriptor::ScalarDescriptor<$field_type>,
                    $crate::schema::descriptor::ScalarDescriptor::new
                )
            ) -> (
                $($tail)*
            )
        );
    };

    // Internal pattern: emit final struct.
    (
        @parse_body(
            $schema_name:ident,
            $(
                ($field_name:ident, $field_def:ty, $field_new:expr)
            ),*
        ) -> ()
    ) => {
        pub struct $schema_name {
            $(
                pub $field_name: $field_def,
            )*
        }

        impl $schema_name {
            pub fn new() -> Self {
                Self {
                    $(
                        $field_name: $field_new(
                            stringify!($schema_name),
                            stringify!($field_name)
                        ),
                    )*
                }
            }
        }
    }
}
