#![feature(conservative_impl_trait)]
#![feature(drain_filter)]
#![feature(fnbox)]

use std::collections::HashMap;

extern crate futures;
extern crate rusoto_core;
extern crate rusoto_dynamodb;
use rusoto_dynamodb::DynamoDb;

extern crate ekiden_common;
use ekiden_common::bytes::H256;
use ekiden_common::futures::BoxFuture;
use ekiden_common::futures::Future;
extern crate ekiden_storage_base;

mod waitloop;

pub struct DynamoDbBackend {
    client: std::sync::Arc<rusoto_dynamodb::DynamoDbClient>,
    executor: waitloop::BoxyRemote,
    table_name: String,
}

impl DynamoDbBackend {
    pub fn new(region: rusoto_core::Region, table_name: String) -> Self {
        Self {
            client: std::sync::Arc::new(rusoto_dynamodb::DynamoDbClient::simple(region)),
            executor: waitloop::BoxyRemote::spawn(),
            table_name,
        }
    }
}

const ATTRIBUTE_ES_KEY: &str = "es_key";
const ATTRIBUTE_ES_VALUE: &str = "es_value";

impl ekiden_storage_base::StorageBackend for DynamoDbBackend {
    fn get(&self, key: H256) -> BoxFuture<Vec<u8>> {
        let client = self.client.clone();
        let table_name = self.table_name.clone();
        Box::new(
            self.executor
                .proxy(move || {
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
                })
                .then(|result| match result {
                    Ok(output) => Ok(output
                        .item
                        .expect("DynamoDbBackend: get_item output must have item")
                        .remove(ATTRIBUTE_ES_VALUE)
                        .expect("DynamoDbBackend: get_item item must have es_value")
                        .b
                        .expect("DynamoDbBackend: get_item es_value must be bytes")),
                    Err(e) => Err(e.into()),
                }),
        )
    }

    fn insert(&self, value: Vec<u8>, _expiry: u64) -> BoxFuture<()> {
        let key = ekiden_storage_base::hash_storage_key(&value);
        let client = self.client.clone();
        let table_name = self.table_name.clone();
        Box::new(
            self.executor
                .proxy(move || {
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
                            item
                        },
                        table_name,
                        ..Default::default()
                    })
                })
                .then(|result| match result {
                    Ok(_output) => Ok(()),
                    Err(e) => Err(e.into()),
                }),
        )
    }
}

#[cfg(test)]
mod tests {
    use ekiden_common::futures::Future;
    use ekiden_storage_base;
    use ekiden_storage_base::StorageBackend;

    use DynamoDbBackend;
    #[test]
    fn play() {
        let storage = DynamoDbBackend::new("us-west-2".parse().unwrap(), "test".to_string());
        let reference_value = vec![1, 2, 3];
        let reference_key = ekiden_storage_base::hash_storage_key(&reference_value);
        storage.insert(reference_value.clone(), 55).wait().unwrap();
        let roundtrip_value = storage.get(reference_key).wait().unwrap();
        assert_eq!(roundtrip_value, reference_value);
    }
}
