use std::collections::HashMap;
use std::sync::Arc;

extern crate clap;
use clap::value_t_or_exit;
extern crate futures;
extern crate rusoto_core;
extern crate rusoto_dynamodb;
use rusoto_dynamodb::DynamoDb;

extern crate ekiden_common;
use ekiden_common::bytes::H256;
use ekiden_common::error::Error;
use ekiden_common::futures::BoxFuture;
use ekiden_common::futures::Future;
use ekiden_common::futures::FutureExt;
extern crate ekiden_di;
use ekiden_di::create_component;
extern crate ekiden_storage_base;
use ekiden_storage_base::{InsertOptions, StorageBackend};

/// A storage backend that uses Amazon DynamoDB.
pub struct DynamoDbBackend {
    client: Arc<rusoto_dynamodb::DynamoDbClient>,
    table_name: String,
}

impl DynamoDbBackend {
    /// Create an instance configured to use a given table name in a given region. Uses the default
    /// Rusoto methods of getting credentials (see
    /// https://github.com/rusoto/rusoto/blob/rusoto-v0.32.0/AWS-CREDENTIALS.md). You must provide
    /// a reactor core remote for spawning internal non-Send futures.
    pub fn new(region: rusoto_core::Region, table_name: String) -> Self {
        Self {
            client: Arc::new(rusoto_dynamodb::DynamoDbClient::new(region)),
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
        client
            .get_item(rusoto_dynamodb::GetItemInput {
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
            .then(move |result| match result {
                Ok(output) => Ok(output
                    .item
                    .ok_or_else(move || {
                        Error::new(format!("DynamoDbBackend: item not present for key {}", key))
                    })?
                    .remove(ATTRIBUTE_ES_VALUE)
                    .expect("DynamoDbBackend: get_item item must have es_value")
                    .b
                    .expect("DynamoDbBackend: get_item es_value must be bytes")),
                Err(e) => Err(e.into()),
            })
            .into_box()
    }

    fn get_batch(&self, _keys: Vec<H256>) -> BoxFuture<Vec<Option<Vec<u8>>>> {
        unimplemented!();
    }

    fn insert(&self, value: Vec<u8>, _expiry: u64, _opts: InsertOptions) -> BoxFuture<()> {
        let key = ekiden_storage_base::hash_storage_key(&value);
        let client = self.client.clone();
        let table_name = self.table_name.clone();
        client
            .put_item(rusoto_dynamodb::PutItemInput {
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
            .then(|result| match result {
                Ok(_output) => Ok(()),
                Err(e) => Err(e.into()),
            })
            .into_box()
    }

    fn insert_batch(&self, _values: Vec<(Vec<u8>, u64)>, _opts: InsertOptions) -> BoxFuture<()> {
        unimplemented!();
    }

    fn get_keys(&self) -> BoxFuture<Arc<Vec<(H256, u64)>>> {
        unimplemented!();
    }
}

fn di_factory(
    container: &mut ekiden_di::Container,
) -> ekiden_di::error::Result<Box<std::any::Any>> {
    let args = container.get_arguments().unwrap();
    let region = value_t_or_exit!(args, "storage-dynamodb-region", rusoto_core::region::Region);
    let table_name = args.value_of("storage-dynamodb-table-name")
        .unwrap()
        .to_string();
    let backend: Arc<StorageBackend> = Arc::new(DynamoDbBackend::new(region, table_name));
    Ok(Box::new(backend))
}

fn di_arg_region<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-dynamodb-region")
        .long("storage-dynamodb-region")
        .help("AWS region that the DynamoDB storage backend should use")
        .takes_value(true)
        .required(true)
}

fn di_arg_table_name<'a, 'b>() -> clap::Arg<'a, 'b> {
    clap::Arg::with_name("storage-dynamodb-table-name")
        .long("storage-dynamodb-table-name")
        .help("DynamoDB table that the DynamoDB storage backend should use")
        .takes_value(true)
        .required(true)
}

// Register for dependency injection. This preparation starts a thread for the reactor core that
// runs forever.
create_component!(
    dynamodb,
    "storage-backend",
    DynamoDbBackend,
    StorageBackend,
    di_factory,
    [di_arg_region(), di_arg_table_name()]
);

#[cfg(test)]
mod tests {
    use ekiden_common;
    use ekiden_storage_base;
    use ekiden_storage_base::{InsertOptions, StorageBackend};
    extern crate log;
    use self::log::warn;
    use rusoto_core;
    use rusoto_core::ProvideAwsCredentials;
    extern crate tokio;

    use DynamoDbBackend;
    #[test]
    fn play() {
        let mut runtime = tokio::runtime::Runtime::new().unwrap();

        if let Err(e) = runtime.block_on(
            rusoto_core::DefaultCredentialsProvider::new()
                .unwrap()
                .credentials(),
        ) {
            // Skip this if AWS credentials aren't available.

            ekiden_common::testing::try_init_logging();
            warn!("{} Skipping DynamoDB test.", e);
            return;
        }

        let storage = DynamoDbBackend::new("us-west-2".parse().unwrap(), "test".to_string());
        let reference_value = vec![1, 2, 3];
        let reference_key = ekiden_storage_base::hash_storage_key(&reference_value);
        runtime
            .block_on(storage.insert(reference_value.clone(), 55, InsertOptions::default()))
            .unwrap();
        let roundtrip_value = runtime.block_on(storage.get(reference_key)).unwrap();
        assert_eq!(roundtrip_value, reference_value);
    }
}
