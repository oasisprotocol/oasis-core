/// Version key used in serialized form.
pub const VERSION_KEY: &str = "v";

/// A generic versioned serializable data structure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Versioned<T> {
    pub version: u16,
    pub inner: T,
}

impl<T> Versioned<T> {
    /// Create a new versioned structure.
    pub fn new(version: u16, inner: T) -> Self {
        Self { version, inner }
    }
}

impl<T: cbor::EncodeAsMap> cbor::Encode for Versioned<T> {
    fn into_cbor_value(self) -> cbor::Value {
        let mut inner = cbor::EncodeAsMap::into_cbor_map(self.inner);
        // Add version to the given map.
        let key = cbor::values::IntoCborValue::into_cbor_value(VERSION_KEY);
        inner.push((key, self.version.into_cbor_value()));
        cbor::Value::Map(inner)
    }
}

impl<T: cbor::Decode> cbor::Decode for Versioned<T> {
    fn try_from_cbor_value(value: cbor::Value) -> Result<Self, cbor::DecodeError> {
        match value {
            cbor::Value::Map(mut items) => {
                // Take the version field from the map and decode the rest.
                let key = cbor::values::IntoCborValue::into_cbor_value(VERSION_KEY);
                let (index, _) = items
                    .iter()
                    .enumerate()
                    .find(|(_, v)| v.0 == key)
                    .ok_or(cbor::DecodeError::MissingField)?;
                let version = items.remove(index).1;

                Ok(Self {
                    version: cbor::Decode::try_from_cbor_value(version)?,
                    inner: cbor::Decode::try_from_cbor_value(cbor::Value::Map(items))?,
                })
            }
            _ => Err(cbor::DecodeError::UnexpectedType),
        }
    }
}
