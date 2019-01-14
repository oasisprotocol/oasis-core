use ekiden_core::runtime::runtime_api;

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyValue {
    pub key: String,
    pub value: String,
}

runtime_api! {
    // Inserts key and corresponding value and returns old value, if any.
    // Both parameters are passed using a single serializable struct KeyValue.
    pub fn insert(KeyValue) -> Option<String>;

    // Gets value associated with given key.
    pub fn get(String) -> Option<String>;

    // Removes value associated with the given key and returns old value, if any.
    pub fn remove(String) -> Option<String>;
}
