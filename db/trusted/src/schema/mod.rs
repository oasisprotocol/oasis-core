//! Higher-level schema-based database interface.
pub mod descriptor;

#[doc(hidden)]
#[macro_use]
pub mod macros;

#[cfg(test)]
mod tests {
    extern crate test;

    use self::test::Bencher;

    use ekiden_common::bytes::{B160, B256};

    use super::super::{Database, DatabaseHandle};

    database_schema! {
        pub struct TestSchema {
            pub foo: String,
            pub bar: String,
            pub moo: u64,
            pub balance_of: Map<String, u64>,
        }

        pub struct AnotherSchema {
            pub foo: String,
            pub bar: String,
        }

        pub struct BenchSchema {
            pub map: Map<(B160, B256), B256>,
        }
    }

    #[test]
    fn test_operations() {
        {
            let mut db = DatabaseHandle::instance();
            db.clear();
        }

        let schema = TestSchema::new();

        // Test scalars.
        assert!(!schema.foo.is_present());
        assert!(!schema.bar.is_present());
        assert!(!schema.moo.is_present());

        assert_eq!(schema.foo.insert("hello world"), None);
        assert_eq!(schema.moo.insert(&42), None);

        assert!(schema.foo.is_present());
        assert!(!schema.bar.is_present());
        assert!(schema.moo.is_present());

        assert_eq!(schema.foo.get(), Some("hello world".to_owned()));
        assert_eq!(schema.moo.get(), Some(42));

        assert_eq!(schema.moo.remove(), Some(42));
        assert!(!schema.moo.is_present());

        assert_eq!(schema.foo.insert("another"), Some("hello world".to_owned()));

        // Test map.
        assert_eq!(schema.balance_of.insert("inner_key", &42), None);
        assert!(schema.balance_of.contains_key("inner_key"));
        assert!(!schema.balance_of.contains_key("foo"));

        assert_eq!(schema.balance_of.insert("inner_key", &100), Some(42));
    }

    #[test]
    fn test_namespaces() {
        {
            let mut db = DatabaseHandle::instance();
            db.clear();
        }

        let schema1 = TestSchema::new();
        let schema2 = AnotherSchema::new();

        assert!(!schema1.foo.is_present());
        assert!(!schema1.bar.is_present());
        assert!(!schema2.foo.is_present());
        assert!(!schema2.bar.is_present());

        assert_eq!(schema1.foo.insert("hello"), None);

        assert!(schema1.foo.is_present());
        assert!(!schema2.foo.is_present());

        assert_eq!(schema2.foo.insert("world"), None);

        assert_eq!(schema1.foo.get(), Some("hello".to_owned()));
        assert_eq!(schema2.foo.get(), Some("world".to_owned()));
    }

    #[bench]
    fn bench_map_insert_random(b: &mut Bencher) {
        {
            let mut db = DatabaseHandle::instance();
            db.clear();
        }

        let schema = BenchSchema::new();

        b.iter(|| {
            schema
                .map
                .insert(&(B160::random(), B256::random()), &B256::zero());
        });
    }
}
