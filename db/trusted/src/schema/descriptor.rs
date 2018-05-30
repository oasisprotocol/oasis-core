//! Field descriptors used in the schema-based interface.
use std::borrow::Borrow;
use std::marker::PhantomData;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;

use super::super::{Database, DatabaseHandle};

/// Descriptor for scalar fields.
pub struct ScalarDescriptor<T> {
    namespace: &'static str,
    name: &'static str,
    value_type: PhantomData<T>,
}

/// Descriptor for map fields.
pub struct MapDescriptor<K, V> {
    namespace: &'static str,
    name: &'static str,
    key_type: PhantomData<K>,
    value_type: PhantomData<V>,
}

impl<T> ScalarDescriptor<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Create new scalar descriptor.
    pub fn new(namespace: &'static str, name: &'static str) -> Self {
        Self {
            namespace: &namespace,
            name: &name,
            value_type: PhantomData,
        }
    }

    /// Derive the key for storing this field in the underlying database.
    fn get_key(&self) -> Vec<u8> {
        serde_cbor::to_vec(&(&self.namespace, &self.name)).unwrap()
    }

    /// Insert a value for this field.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// The value may be any borrowed form of the descriptor's value type, but [`Serialize`]
    /// on the borrowed form must match those for the value type.
    ///
    /// [`None`]: std::option::Option
    /// [`Serialize`]: serde::Serialize
    pub fn insert<Q>(&self, value: &Q) -> Option<T>
    where
        T: Borrow<Q>,
        Q: ?Sized + Serialize,
    {
        let mut db = DatabaseHandle::instance();
        let value = serde_cbor::to_vec(&(value.borrow())).unwrap();
        match db.insert(&self.get_key(), &value) {
            Some(value) => Some(serde_cbor::from_slice(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Fetch a value for this field.
    pub fn get(&self) -> Option<T> {
        let db = DatabaseHandle::instance();
        match db.get(&self.get_key()) {
            Some(value) => Some(serde_cbor::from_slice(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Remove a value for this field, returning the value at the key if the key was previously
    /// in the database.
    pub fn remove(&self) -> Option<T> {
        let mut db = DatabaseHandle::instance();
        match db.remove(&self.get_key()) {
            Some(value) => Some(serde_cbor::from_slice(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Check if a field is present in the underlying database.
    pub fn is_present(&self) -> bool {
        let db = DatabaseHandle::instance();
        db.contains_key(&self.get_key())
    }
}

impl<K, V> MapDescriptor<K, V>
where
    K: Serialize,
    V: Serialize + DeserializeOwned,
{
    /// Create new map descriptor.
    pub fn new(namespace: &'static str, name: &'static str) -> Self {
        Self {
            namespace: &namespace,
            name: &name,
            key_type: PhantomData,
            value_type: PhantomData,
        }
    }

    /// Derive the key for storing this field in the underlying database.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serialize`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serialize`]: serde::Serialize
    fn get_key_for_subkey<Q>(&self, subkey: &Q) -> Vec<u8>
    where
        K: Borrow<Q>,
        Q: ?Sized + Serialize,
    {
        serde_cbor::to_vec(&(&self.namespace, &self.name, subkey)).unwrap()
    }

    /// Insert a value for this field.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serialize`]
    /// on the borrowed form must match those for the key type.
    ///
    /// The value may be any borrowed form of the descriptor's value type, but [`Serialize`]
    /// on the borrowed form must match those for the value type.
    ///
    /// [`None`]: std::option::Option
    /// [`Serialize`]: serde::Serialize
    pub fn insert<Q, P>(&self, key: &Q, value: &P) -> Option<V>
    where
        K: Borrow<Q>,
        V: Borrow<P>,
        Q: ?Sized + Serialize,
        P: ?Sized + Serialize,
    {
        let mut db = DatabaseHandle::instance();
        let value = serde_cbor::to_vec(&(value.borrow())).unwrap();
        match db.insert(&self.get_key_for_subkey(key), &value) {
            Some(value) => Some(serde_cbor::from_slice(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Fetch a value for this field.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serialize`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serialize`]: serde::Serialize
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Serialize,
    {
        let db = DatabaseHandle::instance();
        match db.get(&self.get_key_for_subkey(key)) {
            Some(value) => Some(serde_cbor::from_slice(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Remove a value for this field, returning the value at the key if the key was previously
    /// in the database.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serialize`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serialize`]: serde::Serialize
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Serialize,
    {
        let mut db = DatabaseHandle::instance();
        match db.remove(&self.get_key_for_subkey(key)) {
            Some(value) => Some(serde_cbor::from_slice(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Check if a field is present in the underlying database.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serialize`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serialize`]: serde::Serialize
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Serialize,
    {
        let db = DatabaseHandle::instance();
        db.contains_key(&self.get_key_for_subkey(key))
    }
}
