//! Field descriptors used in the schema-based interface.
use std::borrow::Borrow;
use std::marker::PhantomData;

use ekiden_common::serializer::{Deserializable, Serializable};

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
    T: Serializable + Deserializable,
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
        let mut key = vec![];
        self.namespace.write_to(&mut key).unwrap();
        self.name.write_to(&mut key).unwrap();

        key
    }

    /// Insert a value for this field.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// The value may be any borrowed form of the descriptor's value type, but [`Serializable`]
    /// on the borrowed form must match those for the value type.
    ///
    /// [`None`]: std::option::Option
    /// [`Serializable`]: ekiden_common::serializer::Serializable
    pub fn insert<Q>(&self, value: &Q) -> Option<T>
    where
        T: Borrow<Q>,
        Q: ?Sized + Serializable,
    {
        let mut db = DatabaseHandle::instance();
        let value = Serializable::write(value.borrow()).expect("Failed to serialize state");
        match db.insert(&self.get_key(), &value) {
            Some(value) => Some(Deserializable::read(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Fetch a value for this field.
    pub fn get(&self) -> Option<T> {
        let db = DatabaseHandle::instance();
        match db.get(&self.get_key()) {
            Some(value) => Some(Deserializable::read(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Remove a value for this field, returning the value at the key if the key was previously
    /// in the database.
    pub fn remove(&self) -> Option<T> {
        let mut db = DatabaseHandle::instance();
        match db.remove(&self.get_key()) {
            Some(value) => Some(Deserializable::read(&value).expect("Corrupted state")),
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
    K: Serializable,
    V: Serializable + Deserializable,
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
    /// The key may be any borrowed form of the descriptor's key type, but [`Serializable`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serializable`]: ekiden_common::serializer::Serializable
    fn get_key_for_subkey<Q>(&self, subkey: &Q) -> Vec<u8>
    where
        K: Borrow<Q>,
        Q: ?Sized + Serializable,
    {
        let mut key = vec![];
        self.namespace.write_to(&mut key).unwrap();
        self.name.write_to(&mut key).unwrap();
        subkey.write_to(&mut key).unwrap();

        key
    }

    /// Insert a value for this field.
    ///
    /// If the database did not have this key present, [`None`] is returned.
    ///
    /// If the database did have this key present, the value is updated, and the old value is
    /// returned.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serializable`]
    /// on the borrowed form must match those for the key type.
    ///
    /// The value may be any borrowed form of the descriptor's value type, but [`Serializable`]
    /// on the borrowed form must match those for the value type.
    ///
    /// [`None`]: std::option::Option
    /// [`Serializable`]: ekiden_common::serializer::Serializable
    pub fn insert<Q, P>(&self, key: &Q, value: &P) -> Option<V>
    where
        K: Borrow<Q>,
        V: Borrow<P>,
        Q: ?Sized + Serializable,
        P: ?Sized + Serializable,
    {
        let mut db = DatabaseHandle::instance();
        let value = Serializable::write(value.borrow()).expect("Failed to serialize value");
        match db.insert(&self.get_key_for_subkey(key), &value) {
            Some(value) => Some(Deserializable::read(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Fetch a value for this field.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serializable`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serializable`]: ekiden_common::serializer::Serializable
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Serializable,
    {
        let db = DatabaseHandle::instance();
        match db.get(&self.get_key_for_subkey(key)) {
            Some(value) => Some(Deserializable::read(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Remove a value for this field, returning the value at the key if the key was previously
    /// in the database.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serializable`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serializable`]: ekiden_common::serializer::Serializable
    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Serializable,
    {
        let mut db = DatabaseHandle::instance();
        match db.remove(&self.get_key_for_subkey(key)) {
            Some(value) => Some(Deserializable::read(&value).expect("Corrupted state")),
            None => None,
        }
    }

    /// Check if a field is present in the underlying database.
    ///
    /// The key may be any borrowed form of the descriptor's key type, but [`Serializable`]
    /// on the borrowed form must match those for the key type.
    ///
    /// [`Serializable`]: ekiden_common::serializer::Serializable
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: ?Sized + Serializable,
    {
        let db = DatabaseHandle::instance();
        db.contains_key(&self.get_key_for_subkey(key))
    }
}
