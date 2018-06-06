//! DI components for use in clients.
use ekiden_core;
use ekiden_di::{Component, KnownComponents};
use ekiden_registry_client;
use ekiden_scheduler_client;

/// Register known components for dependency injection.
pub fn register_components(known_components: &mut KnownComponents) {
    // Environment.
    ekiden_core::environment::GrpcEnvironment::register(known_components);
    // Scheduler.
    ekiden_scheduler_client::SchedulerClient::register(known_components);
    // Entity registry.
    ekiden_registry_client::EntityRegistryClient::register(known_components);
}

/// Create known component registry.
pub fn create_known_components() -> KnownComponents {
    let mut known_components = KnownComponents::new();
    register_components(&mut known_components);

    known_components
}
