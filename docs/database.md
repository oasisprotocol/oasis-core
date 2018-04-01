# Database

The Ekiden database serves as a persistent state store for contracts.

## Interfaces

Only the trusted API exposed to contracts should be considered relatively stable. **How state is serialized and stored outside the contract and the EDL interface is currently an unstable implementation detail which will change in future versions.**

### Trusted API exposed to contracts

#### Low-level interface

```rust
/// Database interface exposed to contracts.
pub trait Database {
    /// Returns true if the database contains a value for the specified key.
    fn contains_key(&self, key: &[u8]) -> bool;

    /// Fetch entry with given key.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Update entry with given key.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    fn insert(&mut self, key: &[u8], value: &[u8]) -> Option<Vec<u8>>;

    /// Remove entry with given key, returning the value at the key if the key was previously
    /// in the database.
    fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>>;

    /// Clear database state.
    fn clear(&mut self);
}
```

#### Schema-based interface

Since the low-level database interface can be tedious to use, the database also exposes a schema-based interface. Using this interface, you first define a database schema and then database manipulation functions will be generated automatically.

Schema definition looks as follows (see the `database_schema!` macro documentation for more information):
```rust
database_schema! {
    pub struct TestSchema {
        pub foo: String,
        pub bar: String,
        pub moo: u64,
        pub balance_of: Map<String, u64>,
    }

    // Schema structs are namespaced, so defining a struct with a different name
    // will cause its fields to be in a different namespace.
    pub struct AnotherSchema {
        pub foo: String,
        pub bar: String,
    }
}
```

Example use:
```rust
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
```

For scalar fields, field names are translated to underlying database keys as follows:
```
db_key := namespace field_name
```

For map fields, keys are translated to underlying database keys as follows:
```
db_key := namespace field_name key
```

In both cases `namespace` is the name of the structure that defines the schema (e.g., `TestSchema` and `AnotherSchema` in the above example). All strings are encoded as UTF-8.
