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

// CommunicationChannel is IP address / port tuple or similar way to
// contact a running contract instance.

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
    fn launch_contract_instance(
        &mut self, name: string, contract_code_id: CodeId,
        gas: GasToken, min_bond_amount)
        -> Result<CommunicationChannelId, Error>;

    // We need to be able to do lookups by name because applications
    // can have a graph of contracts that need to call each other, and
    // the lack of an acyclic graph means that we cannot e.g. embed
    // the CommunicationChannelId in the contracts' code; instead, we
    // require that at launch, a clique of contracts be given instance
    // names that allow them to find each other.
    fn find_contract_instance(
        &mut self, name: string)
        -> Result<Vec<(CodeId, CommunicationChannelId)>, Error>;

    // This version allows the caller to provide a string name
    // (functionality) and a vector of contract code hashes that the
    // caller knows about and can work with.  No built-in versioning
    // mechanism here.  The caller has to have some trusted mechanism
    // to allow it to specify that a new code hash replaces an old
    // one, or the named contract is really a forwarder to different
    // implementations.
    fn find_contract_instance(
        &mut self, (name: string, Vec<CodeId>))
        -> Result<Vec<(CodeId, CommunicationChannelId)>, Error>;
}

// GlobalScheduler or ReplicaCoordinator to LocalScheduler
pub trait ReplicaCoordinatorToLocalScheduler {
    fn launch_replicated_contract(
        &mut self, name: string, contract_code_id: CodeId, gas: GasToken)
        -> Result<CommunicationChannelId, Error>;
    // CommunicationChannelId used to send remote method invocations.
    // In the case of a replicated contract, this channel may actually
    // be to a proxy implemented by the coordinator which sends
    // requests to all replicas and then checks the answers.  (Do we
    // want the ReplicaCoordinator to be out of the way and not be a
    // potential bottleneck?  But having it be a client library means
    // exposing details of replication strategy.)
}

// Group communications for running replicas of a contract and doing
// honest majority or discrepancy detection.
//
// Anyone can run ReplicaCoordinator, but to mark nodes / punish
// misbehavior, they need to be registered with the GlobalScheduler.

pub trait PublicToReplicaCoordinator {
    // The gas is subdivided evenly across all num_replicas.
    fn launch_replicated_contract_instance(
        &mut self, name: string, contract_code_id: CodeId,
        gas: GasToken, min_bond_amount: Token, num_replicas: uint32)
        -> Result<CommunicationChannelId, Error>;

    fn find_replicated_contract_instance(
        &mut self, name: string)
        -> Result<(CodeId, CommunicationChannelId,
                   min_bond_amount, num_replicas), Error>;

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
        &mut self, Vec<CommunicationChannelId>)
        -> Result<(), Error>;
}
