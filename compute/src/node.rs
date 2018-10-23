//! Compute node.
#[cfg(feature = "testing")]
use std::process::abort;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use grpcio;

use ekiden_compute_api;
use ekiden_core::bytes::B256;
use ekiden_core::environment::Environment;
use ekiden_core::error::Result;
use ekiden_core::futures::Future;
use ekiden_core::identity::{EntityIdentity, NodeIdentity};
use ekiden_core::signature::Signed;
use ekiden_di::Container;
use ekiden_registry_base::{EntityRegistryBackend, Runtime, RuntimeRegistryBackend,
                           REGISTER_ENTITY_SIGNATURE_CONTEXT, REGISTER_NODE_SIGNATURE_CONTEXT,
                           REGISTER_RUNTIME_SIGNATURE_CONTEXT};
use ekiden_roothash_base::{RootHashBackend, RootHashSigner};
use ekiden_rpc_api;
use ekiden_scheduler_base::Scheduler;
use ekiden_storage_api::create_storage;
use ekiden_storage_base::{StorageBackend, StorageService};
use ekiden_tools::get_enclave_identity;

use super::group::ComputationGroup;
use super::ias::{IASConfiguration, IAS};
use super::roothash::{RootHashConfiguration, RootHashFrontend};
use super::services::computation_group::ComputationGroupService;
use super::services::enclaverpc::EnclaveRpcService;
use super::services::runtime::RuntimeService;
use super::worker::{Worker, WorkerConfiguration};

/// Compute node test-only configuration.
pub struct ComputeNodeTestOnlyConfiguration {
    /// Override runtime identifier.
    pub runtime_id: Option<B256>,
    /// Fail after registration.
    pub fail_after_registration: bool,
}

/// Compute node configuration.
pub struct ComputeNodeConfiguration {
    /// gRPC server port.
    pub port: u16,
    /// Number of compute replicas.
    // TODO: Remove this once we have independent runtime registration.
    pub compute_replicas: u64,
    /// Number of compute backup replicas.
    // TODO: Remove this once we have independent runtime registration.
    pub compute_backup_replicas: u64,
    /// Number of allowed stragglers.
    // TODO: Remove this once we have independent runtime registration.
    pub compute_allowed_stragglers: u64,
    /// Root hash configuration.
    pub roothash: RootHashConfiguration,
    /// IAS configuration.
    pub ias: Option<IASConfiguration>,
    /// Worker configuration.
    pub worker: WorkerConfiguration,
    /// Test-only configuration.
    pub test_only: ComputeNodeTestOnlyConfiguration,
}

/// Compute node.
pub struct ComputeNode {
    /// gRPC server.
    server: grpcio::Server,
}

impl ComputeNode {
    /// Create new compute node.
    pub fn new(config: ComputeNodeConfiguration, mut container: Container) -> Result<Self> {
        // Creation time.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        // Create IAS.
        let ias = Arc::new(IAS::new(config.ias)?);

        let runtime_registry = container.inject::<RuntimeRegistryBackend>()?;
        let entity_registry = container.inject::<EntityRegistryBackend>()?;
        let scheduler = container.inject::<Scheduler>()?;
        let storage_backend = container.inject::<StorageBackend>()?;
        let storage_service = create_storage(StorageService::new(
            // TODO: Pass a storage backend that, when using multilayer storage, would allow
            // transition_keys to replicate the appropriate content from the local layer without
            // hassling the last resort layer.
            storage_backend.clone(),
        ));
        let roothash_backend = container.inject::<RootHashBackend>()?;
        let roothash_signer = container.inject::<RootHashSigner>()?;

        // Register entity with the registry.
        // TODO: This should probably be done independently?
        let entity_identity = container.inject::<EntityIdentity>()?;
        info!("Registering entity with the registry");
        entity_registry
            .register_entity(entity_identity.get_signed_entity(&REGISTER_ENTITY_SIGNATURE_CONTEXT))
            .wait()?;
        info!("Entity registration done");

        // Create runtime.
        // TODO: Get this from somewhere.
        // TODO: This should probably be done independently?
        // TODO: We currently use the entity key pair as the runtime key pair.
        let runtime_id = match config.test_only.runtime_id {
            Some(runtime_id) => {
                warn!("Using manually overriden runtime id");
                runtime_id
            }
            None => {
                B256::from(get_enclave_identity(config.worker.runtime_filename.clone())?.as_slice())
            }
        };

        info!("Running compute node for runtime {:?}", runtime_id);
        let runtime = {
            let mut runtime = Runtime::default();
            runtime.id = runtime_id;
            runtime.replica_group_size = config.compute_replicas;
            runtime.replica_group_backup_size = config.compute_backup_replicas;
            runtime.replica_allowed_stragglers = config.compute_allowed_stragglers;
            runtime.storage_group_size = 1;
            runtime.registration_time = now;

            runtime
        };
        let signed_runtime = Signed::sign(
            &entity_identity.get_entity_signer(),
            &REGISTER_RUNTIME_SIGNATURE_CONTEXT,
            runtime.clone(),
        );
        runtime_registry.register_runtime(signed_runtime).wait()?;

        // Register node with the registry.
        let node_identity = container.inject::<NodeIdentity>()?;
        let signed_node = Signed::sign(
            &entity_identity.get_entity_signer(),
            &REGISTER_NODE_SIGNATURE_CONTEXT,
            node_identity.get_node(),
        );
        info!("Registering compute node with the registry");
        entity_registry.register_node(signed_node).wait()?;
        info!("Compute node registration done");

        // Test mode: crash after registration.
        #[cfg(feature = "testing")]
        {
            if config.test_only.fail_after_registration {
                error!("TEST MODE: crashing after registration");
                abort();
            }
        }

        // Environment.
        let environment = container.inject::<Environment>()?;
        let grpc_environment = environment.grpc();

        // Create worker.
        let worker = Arc::new(Worker::new(
            config.worker,
            ias,
            environment.clone(),
            storage_backend.clone(),
        ));

        // Create computation group.
        let computation_group = Arc::new(ComputationGroup::new(
            runtime_id,
            scheduler.clone(),
            entity_registry.clone(),
            environment.clone(),
            node_identity.clone(),
            storage_backend.clone(),
        ));

        // Create roothash frontend.
        let roothash_frontend = Arc::new(RootHashFrontend::new(
            config.roothash,
            runtime_id,
            environment.clone(),
            worker.clone(),
            computation_group.clone(),
            roothash_backend.clone(),
            roothash_signer.clone(),
            storage_backend.clone(),
        ));

        // Create compute node gRPC server.
        use grpcio::ClientCertificateRequestType::RequestClientCertificateButDontVerify;

        let enclave_rpc_service =
            ekiden_rpc_api::create_enclave_rpc(EnclaveRpcService::new(worker));
        let runtime_service =
            ekiden_compute_api::create_runtime(RuntimeService::new(roothash_frontend.clone()));
        let inter_node_service = ekiden_compute_api::create_computation_group(
            ComputationGroupService::new(roothash_frontend.clone()),
        );
        let server = grpcio::ServerBuilder::new(grpc_environment.clone())
            .channel_args(
                grpcio::ChannelBuilder::new(grpc_environment.clone())
                    .max_receive_message_len(i32::max_value())
                    .max_send_message_len(i32::max_value())
                    .build_args(),
            )
            .register_service(enclave_rpc_service)
            .register_service(inter_node_service)
            .register_service(runtime_service)
            .register_service(storage_service)
            .bind_secure(
                "0.0.0.0",
                config.port,
                grpcio::ServerCredentialsBuilder::new()
                    .root_cert(node_identity.get_tls_certificate().get_pem()?, true)
                    .client_certificate_request_type(RequestClientCertificateButDontVerify)
                    .add_cert(
                        node_identity.get_tls_certificate().get_pem()?,
                        node_identity.get_tls_private_key().get_pem()?,
                    )
                    .build(),
            )
            .build()?;

        Ok(Self { server })
    }

    /// Start compute node.
    pub fn start(&mut self) {
        // Start gRPC server.
        self.server.start();

        for &(ref host, port) in self.server.bind_addrs() {
            info!("Compute node listening on {}:{}", host, port);
        }
    }
}
