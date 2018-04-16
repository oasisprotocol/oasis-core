// TODO: This needs to be made to be real Rust, and be split out into
// separate trait files(?).

// The players:
//
// GlobalScheduler -- there can actually be more than one, but
// miners/compute nodes should normally register to only one.  It
// handles compute node service advertisements and correctness bonds.
// It is also responsible for randomly picking an available compute
// node (with sufficient bond) to run contract code.  (*TODO* do we
// need to separate out this as a policy?)
//
// ComputeNode -- Offers to host contract computation.  If a compute
// node is not available when asked to launch or (in the case where a
// replica coordinator is used) is detected to compute inorrectly,
// (some of) the compute node's bond is forfeit.
//
// ReplicaCoordinator -- Users can request it to launch a contract to
// run on a certain number of replicas.  Different ReplicaCoordinator
// implementations can implement different policies (honest majority,
// full agreement with discrepancy detection, or other threshold).
//
// For initial versions, the GlobalScheduler and ReplicaCoordinator
// traits might be implemented by the same object.
//
// Public -- any user.

// Type names are suggestive. We may have existing types that work.


pub trait ComputeNodeToGlobalScheduler {
    // After ttl_seconds the service advertisement and bond is
    // automatically released.
    fn register_compute_node(
        &mut self, local_scheduler: CommunicationChannelId,
        ttl_seconds : uint32,  // 136 years max
        correctness_bond: Tokens, fee: GasTokens)
        -> Result<(), Error>;

    // Explicit deregistration -- need to shutdown the node, etc.
    // Paid for in register_compute_node.  DOS attacker can cost the
    // GlobalScheduler the authentication overhead in the RPC and the
    // local_scheduler lookup cost.
    fn deregister_compute_node(
        &mut self, local_scheduler: CommunicationChannelId)
        -> Result<(), Error>;
}

pub trait PublicToGlobalScheduler {
    // Pick a compute node and tell it to launch an instance of
    // contract_code_id.  Returns the communication channel that the
    // client can use to interact with the contract instance.
    //
    // This runs a single contract instance and does not handle
    // replication.
    fn launch_contract(
        &mut self, contract_code_id: CodeId, gas: GasToken,
        min_bond_amount)
        -> Result<CommunicationChannelId, Error>;

// GlobalScheduler or ReplicaCoordinator to LocalScheduler
pub trait ReplicaCoordinatorToLocalScheduler {
    fn launch_replicated_contract(
        &mut self, contract_code_id: CodeId, gas: GasToken)
        -> Result<CommunicationChannelId, Error>;
    // CommunicationChannelId used to send remote method invocations
    // Must be comparable.
}

// Group communications for running replicas of a contract and doing
// honest majority or discrepancy detection.
//
// Anyone can run ReplicaCoordinator, but to mark nodes / punish
// misbehavior, they need to be registered with the GlobalScheduler.

pub trait PublicToReplicaCoordinator {
    // The gas is subdivided evenly across all num_replicas.
    fn launch(
        &mut self, contract_code_id: CodeId,
        gas: GasToken, min_bond_amount, num_replicas)
        -> Result<CommunicationChannelId, Error>;
    }
}

// How does GlobalScheduler authenticate a ReplicaCoordinator as
// legitimate/acceptable?  We do authenticated RPCs, so registration
// is just to name an instance, and a previously registered instance
// can punish a compute node.
pub trait ReplicaCoordinatorToGlobalScheduler {
    // Basically the same as compute node?  Are there any checks
    // on the correctness of a replica coordinator?  Does it only
    // ensure that the replica group has all signed, etc?
    fn register_replica_coordinator(
        &mut self, replica_coordinator: CommunicationChannelId,
        ttl_seconds,
        correctness_bond: Tokens, fee: GasTokens)
        -> Result<(), Error>;

    // Only legitimate ReplicaCoordinators should be able to do this.
    fn punish_compute_nodes(
        &mut self, List<CommunicationChannelId>)
        -> Result<(), Error>;
                
}
