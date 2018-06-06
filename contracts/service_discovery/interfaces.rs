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
// ConsensusBackend -- determine outcome based on replica group chosen
// by ReplicaCoordinator
//
// Public -- any user.

// Type names are suggestive. We may have existing types that work.
// CommunicationChannelId: IP address/port pair, possibly including a
// public key as good for communicating with the entity associated
// with the channel, and the CodeId and StateId for identifying the
// contract instance.  A CodeId is the cryptographic hash of the code,
// and the StateId is the name of the blockchain used and state name
// used to persist the contract instance's state onto the blockchain.
//
// TBD: is it always the case that the sender of the
// CommunicationChannelId that asserts that the key is good for this,
// or do we need a certification mechanism?  In the case of SGX, the
// "init" LocalScheduler launcher might be a reasonable certifier.  Do
// we also need to include state_id as assigned by the
// blockchain/storage?

// A contract instance is unique given the CodeId and StateId values.
// However, this does not help us locate the instance on the network.
// For location and authenticating the instance, we need the IP
// address, TCP port number, and some way to authenticate that
// instance in an enum.  For the SGX/enclave case, the attested public
// key (or key hash) that the contract instance generated at startup;
// for the no-private-data case, we may want to include a self-signed
// cert or a public key hash for leap-of-faith identities (this would
// be vulnerable to Sybil attacks except that we have correctness_bond
// / stake).

// TBD: do we really need both StateId and authentication info?  This
// is needed if a given authentication info (ephemeral public key
// generated during enclave startup) might be used with two or more
// state stores, but maybe we should just disallow this since a
// contract instance keeping state on two blockchains is weird, except
// for something like a contract that is doing cryptocurrency trading.
// Such a thing might be desirable, but the two (or more) blockchains
// will reach consensus independently, and that is awkward.

pub trait ComputeNodeToGlobalScheduler {
    // Register a compute node as available for running contract
    // instances.  The local_scheduler is how the global scheduler
    // talk to the compute node to launch contract instances, etc.
    // system_info contains information with security/performance
    // implications: additional instruction set extensions, memory
    // available for running enclaves, expected I/O bandwidth
    // available to network, etc.  After ttl the service advertisement
    // and bond is automatically released.
    fn register_compute_node(
        &mut self,
        local_scheduler: CommunicationChannelId,
        system_info: string,
        ttl: uint32,  // TODO: is this in seconds, in which case
        // uint32 means a max of 136 years?  Or randomness beacon
        // epochs?  If it is real time, some limited amount of clock
        // drift is okay (?); and NTPsec might be in the future.  The
        // cost to maintain the list of compute nodes is O(number of
        // epochs) or ...?  Users do not get access to the list, since
        // the GlobalScheduler alone (randomly) picks compute nodes on
        // which to run contracts.  We get O(n) fee for registering n
        // nodes, but cost is probably more like O(t n log n) where t
        // is the TTL duration in time or epochs, depending on how the
        // cost of memory storage is amortized/depreciated over time.
        correctness_bond: StakingTokens, fee: GasTokens)
        -> Result<(), Error>;

    // Explicit deregistration -- need to shutdown the node, etc.  DOS
    // attacker can cost the GlobalScheduler the authentication
    // overhead in the RPC and the local_scheduler lookup cost, so
    // there is always a fee -- even though we could have lumped it
    // into the register_compute_node fee, a DOS call would not be
    // paid for with a corresponding registration.
    fn deregister_compute_node(
        &mut self, local_scheduler: CommunicationChannelId, fee: GasToken)
        -> Result<(), Error>;
}

pub trait PublicToGlobalScheduler {
    // Randomly pick a compute node and tell it to launch an instance
    // of contract_code_id.  Returns the communication channel that
    // the client can use to interact with the contract instance.
    //
    // The contract_code_id is used to identify contract code to load
    // into a contract instance.  For a given CodeId, there could be
    // more than one contract instances running, even on the same
    // machine, and definitely on multiple machines, so the returned
    // CommunicationChannelId will fill in the StateId that the code
    // obtained from the blockchain (see configuration) and the TCP
    // addr/port and authentication info.
    //
    // static_configuration is a JSON (field names TBD) specifying the
    // requirements for running the contract.  See discussion in the
    // PublicToReplicaCoordinator launch_replicated_contract for
    // description of what goes in this field.  Replication info is
    // ignored, since that is the concern being addressed by the
    // ReplicaCoordinator.
    //
    // This runs a single contract instance and does not handle
    // replication, migration, etc.
    fn launch_contract_instance(
        &mut self, contract_code_id: CodeId,
        configuration_requirements: string,
        gas: GasToken)
        -> Result<CommunicationChannelId, Error>;

    // Contract migration: add interfaces to tell a LocalScheduler to
    // coordinate with another to tell the a new contract instance to
    // handshake with an already running contract instance and
    // atomically transfer the ephemeral key?

    // Suppose we had contract instances A, B, and C.  A needs to call
    // B, B needs to call C, and C needs to call A.  There is a cycle.
    // While we might launch C first, and embed C's
    // CommunicationChannelId in B's state, launch B, then similarly
    // embed B's CommunicationChannelId in A's state, when we launch A
    // we cannot retroactively take A's CommunicationChannelId and
    // embed it in C's state.  Instead, C has to have some private
    // configuration interface to accept info about A dynamically, at
    // runtime.  Rather than actually changing a contract's initial
    // state, we expect that all contracts of this nature to require
    // the contract authors to collectively sign and provide dynamic
    // configuration information, and the contract code would be
    // written so that no method calls would be accepted until this
    // dynamic configuration has taken place.
}

// GlobalScheduler or ReplicaCoordinator to LocalScheduler
pub trait ReplicaCoordinatorToLocalScheduler {
    fn launch_replicated_contract(
        &mut self, contract_code_id: CodeId, gas: GasToken)
        -> Result<CommunicationChannelId, Error>;
    // CommunicationChannelId used to send remote method invocations.
}

// Group communications for running replicas of a contract and doing
// honest majority or discrepancy detection.
//
// configuration is a JSON (field names TBD) specifying the
// requirements for running the contract, e.g, a set of acceptable
// blockchain ids (usually singleton, but maybe for availability
// contract author may allow a set?), whether the contract code must
// be run in SGX, the replication strategy to use (honest majority,
// discrepancy detection, others), size of replica group, etc.  One
// field will be a minimum bond amount, so the contract author can
// specify that the contract will only run on compute nodes with at
// least that amount of bond.  (This may be bucketed.)
//
// Perhaps in the future anyone can write and run ReplicaCoordinators
// (in the microkernel style), but to mark nodes / punish misbehavior,
// they need to be registered with the GlobalScheduler, since we need
// to trust ReplicaCoordinators to mark nodes correctly.

pub trait PublicToReplicaCoordinator {
    // The gas is subdivided evenly across all num_replicas.
    fn launch_replicated_contract_instance(
        &mut self, name: string, contract_code_id: CodeId,
        configuration: string,
        gas: GasToken)
        -> Result<CommunicationChannelId, Error>;
    // Because this is a replicated contract, the returned channel may
    // actually be to a proxy implemented by the coordinator or a
    // leader in the replication group which sends (forwards) requests
    // to all replicas and then checks the answers.  (Do we want the
    // ReplicaCoordinator to be out of the way and not be a potential
    // bottleneck?  But having it be a client library means exposing
    // details of replication strategy.)
}

// How does the ConsensusBackend send its decision on what is the
// consensus value to the entity that needs to know?  Is this the
// leader of a replica group, or the caller of the method?
pub trait ConsensusBackendToReplicaCoordinator {
    fn find_replicated_contract_instance(
        &mut self, leader: CommunicationChannelId, fee: GasToken)
        -> Result<Vec<CommunicationChannelId>, Error>;
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
