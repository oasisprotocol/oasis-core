use std::result::Result as StdResult;

use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
#[allow(unused_imports)]
use ekiden_common::futures::Future;
use ekiden_di;

use web3;
use web3::Web3;

struct LocalIdentity {}

create_component!(
    ethereum,
    "identiy",
    LocalIdentity,
    Entity,
    (|container: &mut Container| -> StdResult<Box<Any>, ekiden_di::error::Error> {
        let has_addr = {
            let args = container.get_arguments().unwrap();
            args.is_present("ethereum-address")
        };
        let eth_address = if has_addr {
            let args = container.get_arguments().unwrap();
            let address = value_t_or_exit!(args, "ethereum-address", H160);
            Some(address)
        } else {
            match container.inject::<Web3<web3::transports::WebSocket>>() {
                Ok(client) => {
                    // TODO: unfortunate wait to resolve call to get local accts.
                    let accounts = client.personal().list_accounts().wait();
                    match accounts {
                        Ok(accts) => if accts.len() > 0 {
                            Some(H160(accts[0].0))
                        } else {
                            None
                        },
                        Err(_) => None,
                    }
                }
                Err(_) => None,
            }
        };

        // TODO: restoring/maintaining local B256 signing keypair from disk.
        Ok(Box::new(Arc::new(Entity {
            id: B256::default(),
            eth_address: eth_address,
        })))
    }),
    [Arg::with_name("ethereum-address")
        .long("ethereum-address")
        .help("address for local ethereum identiy")
        .takes_value(true)]
);
