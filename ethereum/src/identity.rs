//! Dependency Injection for the local node's identity
use std::fs::File;
use std::net::SocketAddr;
use std::result::Result as StdResult;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_cbor;
use web3;
use web3::Web3;

use ekiden_common::address::Address;
use ekiden_common::bytes::H160;
use ekiden_common::entity::Entity;
#[allow(unused_imports)]
use ekiden_common::futures::Future;
use ekiden_common::identity::{EntityIdentity, NodeIdentity};
use ekiden_common::node::Node;
use ekiden_common::ring::rand::SystemRandom;
use ekiden_common::ring::signature::Ed25519KeyPair;
use ekiden_common::signature::{InMemorySigner, Signer};
use ekiden_common::untrusted;
use ekiden_common::x509;
use ekiden_di::error::Error as DiError;

/// Persistent key pair.
trait KeyPair {
    /// Generate a new key pair.
    fn generate() -> Self;

    /// Get Ed25519 seed.
    fn get_seed(&self) -> &[u8];

    /// Generate a signer from the key pair.
    fn to_signer(&self) -> Arc<Signer> {
        let key_pair = Ed25519KeyPair::from_pkcs8(untrusted::Input::from(self.get_seed())).unwrap();
        Arc::new(InMemorySigner::new(key_pair))
    }
}

/// Helper function for loading or generating a key pair.
fn generate_or_load_key_pair<S>(kind: &str, filename: Option<&str>) -> S
where
    S: KeyPair + Serialize + DeserializeOwned,
{
    let mut key_pair = if let Some(filename) = filename {
        // Load key pair from existing file.
        if let Ok(mut file) = File::open(filename) {
            let key_pair: S = serde_cbor::from_reader(file).unwrap();
            info!("Loaded {} key pair from {}", kind, filename);

            Some(key_pair)
        } else {
            None
        }
    } else {
        None
    };

    if key_pair.is_none() {
        // Generate new key pair.
        info!("Generating new {} key pair", kind);

        let new_key_pair = S::generate();

        if let Some(filename) = filename {
            // Persist key pair to file.
            let mut file = File::create(filename).expect("unable to create key pair file");
            serde_cbor::to_writer(&mut file, &new_key_pair).unwrap();
        }

        key_pair = Some(new_key_pair);
    }

    let key_pair = key_pair.unwrap();

    info!(
        "Using {} public key {:?}",
        kind,
        key_pair.to_signer().get_public_key()
    );

    key_pair
}

/// Ethereum-based entity identity.
pub struct EthereumEntityIdentity {
    /// Entity descriptor.
    entity: Entity,
    /// Signer for the entity.
    signer: Arc<Signer>,
}

impl EthereumEntityIdentity {
    pub fn new(entity: Entity, signer: Arc<Signer>) -> Self {
        Self { entity, signer }
    }
}

impl EntityIdentity for EthereumEntityIdentity {
    fn get_entity(&self) -> Entity {
        self.entity.clone()
    }

    fn get_entity_signer(&self) -> Arc<Signer> {
        self.signer.clone()
    }
}

/// Persistent entity key pair.
#[derive(Serialize, Deserialize)]
struct EntityKeyPair {
    seed: Vec<u8>,
}

impl KeyPair for EntityKeyPair {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let seed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap().to_vec();

        Self { seed }
    }

    fn get_seed(&self) -> &[u8] {
        &self.seed[..]
    }
}

/// Dependency Injection factory for a local `EntityIdentity`. The identity persists
/// and allows user configuration of the entity's long term keypair and ethereum
/// address.
create_component!(
    ethereum_entity,
    "entity-identity",
    EthereumEntityIdentity,
    EntityIdentity,
    (|container: &mut Container| -> StdResult<Box<Any>, DiError> {
        let has_addr = {
            let args = container.get_arguments().unwrap();
            args.is_present("entity-ethereum-address")
        };
        let eth_address = if has_addr {
            let args = container.get_arguments().unwrap();
            let address = value_t_or_exit!(args, "entity-ethereum-address", H160);
            Some(address)
        } else {
            info!("No local identity provided. Attempting to auto-discover through web3.");
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

        // Setup key pair.
        let key_pair: EntityKeyPair = {
            let args = container.get_arguments().unwrap();
            generate_or_load_key_pair("entity", args.value_of("entity-key-pair"))
        };

        let signer = key_pair.to_signer();

        let entity_identity: Arc<EntityIdentity> = Arc::new(EthereumEntityIdentity::new(
            Entity {
                id: signer.get_public_key(),
                eth_address,
            },
            signer,
        ));

        Ok(Box::new(entity_identity))
    }),
    [
        Arg::with_name("entity-ethereum-address")
            .long("entity-ethereum-address")
            .help("Ethereum address for local entity identity")
            .takes_value(true),
        Arg::with_name("entity-key-pair")
            .long("entity-key-pair")
            .help("Path to entity key pair (if not set, a new key pair will be generated)")
            .takes_value(true)
    ]
);

/// Ethereum-based node identity.
pub struct EthereumNodeIdentity {
    /// Node descriptor.
    node: Node,
    /// Signer for the node.
    signer: Arc<Signer>,
    /// TLS certificate.
    tls_certificate: x509::Certificate,
    /// TLS private key.
    tls_private_key: x509::PrivateKey,
}

impl EthereumNodeIdentity {
    pub fn new(
        node: Node,
        signer: Arc<Signer>,
        tls_certificate: x509::Certificate,
        tls_private_key: x509::PrivateKey,
    ) -> Self {
        Self {
            node,
            signer,
            tls_certificate,
            tls_private_key,
        }
    }
}

impl NodeIdentity for EthereumNodeIdentity {
    fn get_node(&self) -> Node {
        self.node.clone()
    }

    fn get_node_signer(&self) -> Arc<Signer> {
        self.signer.clone()
    }

    fn get_tls_certificate(&self) -> &x509::Certificate {
        &self.tls_certificate
    }

    fn get_tls_private_key(&self) -> &x509::PrivateKey {
        &self.tls_private_key
    }
}

/// Persistent node key pair.
#[derive(Serialize, Deserialize)]
struct NodeKeyPair {
    seed: Vec<u8>,
    tls_certificate: x509::Certificate,
    tls_private_key: x509::PrivateKey,
}

impl KeyPair for NodeKeyPair {
    fn generate() -> Self {
        let rng = SystemRandom::new();
        let seed = Ed25519KeyPair::generate_pkcs8(&rng).unwrap().to_vec();
        let (tls_certificate, tls_private_key) = x509::Certificate::generate().unwrap();

        Self {
            seed,
            tls_certificate,
            tls_private_key,
        }
    }

    fn get_seed(&self) -> &[u8] {
        &self.seed[..]
    }
}

/// Validate an IP address + port string.
fn validate_addr_port(v: String) -> Result<(), String> {
    match v.parse::<SocketAddr>() {
        Ok(_) => return Ok(()),
        Err(err) => return Err(err.to_string()),
    }
}

/// Dependency Injection factory for a local `NodeIdentity`. The identity persists
/// and allows user configuration of the entity's long term keypair and ethereum
/// address.
create_component!(
    ethereum_node,
    "node-identity",
    EthereumNodeIdentity,
    NodeIdentity,
    (|container: &mut Container| -> StdResult<Box<Any>, DiError> {
        // Setup key pair.
        let key_pair: NodeKeyPair = {
            let args = container.get_arguments().unwrap();
            generate_or_load_key_pair("node", args.value_of("node-key-pair"))
        };

        let signer = key_pair.to_signer();

        // Generate node descriptor.
        let entity_identity = container.inject::<EntityIdentity>()?;
        let node = Node {
            id: signer.get_public_key(),
            // TODO: support different local node addresses within an entity.
            eth_address: entity_identity.get_entity().eth_address,
            entity_id: entity_identity.get_public_key(),
            expiration: 0xffffffffffffffff,
            addresses: {
                let args = container.get_arguments().unwrap();

                if args.is_present("node-register-addr") {
                    let addresses = values_t_or_exit!(args, "node-register-addr", SocketAddr);
                    let mut result = vec![];
                    for address in addresses {
                        result.push(Address(address.clone()));
                    }

                    result
                } else {
                    let port = value_t!(args, "port", u16).unwrap_or(9001);

                    Address::for_local_port(port).unwrap()
                }
            },
            certificate: key_pair.tls_certificate.clone(),
            stake: vec![],
        };

        info!("Registering compute node addresses: {:?}", node.addresses);

        let node_identity: Arc<NodeIdentity> = Arc::new(EthereumNodeIdentity::new(
            node,
            signer,
            key_pair.tls_certificate,
            key_pair.tls_private_key,
        ));

        Ok(Box::new(node_identity))
    }),
    [
        Arg::with_name("node-key-pair")
            .long("node-key-pair")
            .help("Path to node key pair (if not set, a new key pair will be generated)")
            .takes_value(true),
        Arg::with_name("node-register-addr")
            .long("node-register-addr")
            .help("Address/port(s) to use when registering this node (if not set, all non-loopback local interfaces will be used)")
            .takes_value(true)
            .multiple(true)
            .validator(validate_addr_port)
    ]
);
