#![feature(conservative_impl_trait)]

use std::collections::HashMap;
use std::sync::Arc;

extern crate futures;
extern crate rusoto_core;
extern crate rusoto_dynamodb;
use rusoto_dynamodb::DynamoDb;
extern crate tokio_core;

extern crate ekiden_common;
use ekiden_common::bytes::H256;
use ekiden_common::futures::BoxFuture;
use ekiden_common::futures::Future;
extern crate ekiden_storage_base;

/// A storage backend that uses Amazon DynamoDB.
pub struct DynamoDbBackend {
    remote: tokio_core::reactor::Remote,
    client: Arc<rusoto_dynamodb::DynamoDbClient>,
    table_name: String,
}

impl DynamoDbBackend {
    /// Create an instance configured to use a given table name in a given region. Uses the default
    /// Rusoto methods of getting credentials (see
    /// https://github.com/rusoto/rusoto/blob/rusoto-v0.32.0/AWS-CREDENTIALS.md). You must provide
    /// a reactor core remote for spawning internal non-Send futures.
    pub fn new(
        remote: tokio_core::reactor::Remote,
        region: rusoto_core::Region,
        table_name: String,
    ) -> Self {
        Self {
            remote,
            client: Arc::new(rusoto_dynamodb::DynamoDbClient::simple(region)),
            table_name,
        }
    }

    /// Like `futures::sync::oneshot::spawn_fn`, but `R` doesn't have to be `Send`.
    fn spawn_fn<F, R>(&self, f: F) -> impl futures::Future<Item = R::Item, Error = R::Error>
    where
        F: FnOnce() -> R + Send + 'static,
        R: futures::IntoFuture,
        R::Future: 'static,
        R::Item: Send + 'static,
        R::Error: Send + 'static,
    {
        let (result_tx, result_rx) = futures::sync::oneshot::channel();
        self.remote.spawn(move |_| {
            f().into_future().then(|result| {
                // Don't mind if initiator hung up.
                drop(result_tx.send(result));
                Ok(())
            })
        });
        result_rx.then(|result| result.unwrap())
    }
}

const ATTRIBUTE_ES_KEY: &str = "es_key";
const ATTRIBUTE_ES_VALUE: &str = "es_value";

impl ekiden_storage_base::StorageBackend for DynamoDbBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let client = self.client.clone();
        let table_name = self.table_name.clone();
        Box::new(self.spawn_fn(move || {
            client.get_item(&rusoto_dynamodb::GetItemInput {
                key: {
                    let mut hm = HashMap::with_capacity(1);
                    hm.insert(
                        ATTRIBUTE_ES_KEY.to_string(),
                        rusoto_dynamodb::AttributeValue {
                            b: Some(key.to_vec()),
                            ..Default::default()
                        },
                    );
                    hm
                },
                projection_expression: Some(ATTRIBUTE_ES_VALUE.to_string()),
                table_name,
                ..Default::default()
            })
        }).then(|result| {
            match result {
                Ok(output) => Ok(output
                    .item
                    .expect("DynamoDbBackend: get_item output must have item")
                    .remove(ATTRIBUTE_ES_VALUE)
                    .expect("DynamoDbBackend: get_item item must have es_value")
                    .b
                    .expect("DynamoDbBackend: get_item es_value must be bytes")),
                Err(e) => Err(e.into()),
            }
        }))
    }

    fn insert(&self, value: Vec<u8>, _expiry: u64) -> BoxFuture<()> {
        let key = ekiden_storage_base::hash_storage_key(&value);
        let client = self.client.clone();
        let table_name = self.table_name.clone();
        Box::new(self.spawn_fn(move || {
            client.put_item(&rusoto_dynamodb::PutItemInput {
                item: {
                    let mut item = HashMap::with_capacity(2);
                    item.insert(
                        ATTRIBUTE_ES_KEY.to_string(),
                        rusoto_dynamodb::AttributeValue {
                            b: Some(key.to_vec()),
                            ..Default::default()
                        },
                    );
                    item.insert(
                        ATTRIBUTE_ES_VALUE.to_string(),
                        rusoto_dynamodb::AttributeValue {
                            b: Some(value),
                            ..Default::default()
                        },
                    );
                    // This is intended to store items permanently. But we might want to
                    // record the creation and expiry history too. We might also want to
                    // simulate expiraiton on `get`, if the storage backend interface
                    // recommends it.
                    item
                },
                table_name,
                ..Default::default()
            })
        }).then(|result| match result {
            Ok(_output) => Ok(()),
            Err(e) => Err(e.into()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use ekiden_storage_base;
    use ekiden_storage_base::StorageBackend;
    use tokio_core;

    use DynamoDbBackend;
    #[test]
    fn play() {
        let mut core = tokio_core::reactor::Core::new().unwrap();
        let storage = DynamoDbBackend::new(
            core.remote(),
            "us-west-2".parse().unwrap(),
            "test".to_string(),
        );
        let reference_value = vec![1, 2, 3];
        let reference_key = ekiden_storage_base::hash_storage_key(&reference_value);
        core.run(storage.insert(reference_value.clone(), 55))
            .unwrap();
        let roundtrip_value = core.run(storage.get(reference_key)).unwrap();
        assert_eq!(roundtrip_value, reference_value);
    }
}
