use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::{
    common::crypto::{hash::Hash, signature::PublicKey},
    consensus::{
        registry::{Node, Runtime, TEEHardware},
        roothash::{Block, Error, Message, OpenCommitment},
        scheduler::{Committee, CommitteeKind, Role},
    },
};

use super::ExecutorCommitment;

/// A trait for looking up registry node descriptors.
pub trait NodeLookup {
    fn node(&self, id: PublicKey) -> Result<Node, Error>;
}

/// A trait that validates messages for validity. It can be used for gas accounting.
pub trait MessageValidator {
    fn validate(&self, msgs: &[Message]) -> Result<()>;
}

impl<F> MessageValidator for F
where
    F: Fn(&[Message]) -> Result<()>,
{
    fn validate(&self, msgs: &[Message]) -> Result<()> {
        (*self)(msgs)
    }
}

/// A pool of commitments that can be used to perform
/// discrepancy detection.
///
/// The pool is not safe for concurrent use.
pub struct Pool {
    /// The runtime descriptor this pool is collecting
    /// the commitments for.
    runtime: Runtime,
    /// The committee this pool is collecting the commitments for.
    committee: Committee,
    /// The current protocol round.
    round: u64,
    // The commitments in the pool iff Committee.Kind
    // is scheduler.KindComputeExecutor.
    execute_commitments: HashMap<PublicKey, ExecutorCommitment>,
    // A flag signalling that a discrepancy has been detected.
    discrepancy: bool,
    // The time when the next call to TryFinalize(true) should
    // be scheduled to be executed. Zero means that no timeout is to be scheduled.
    _next_timeout: i64,

    // A cached committee member set. It will be automatically
    // constructed based on the passed Committee.
    member_set: HashSet<PublicKey>,
    // A cached committee worker set. It will be automatically
    // constructed based on the passed Committee.
    _worker_set: HashSet<PublicKey>,
}

impl Pool {
    /// Creates a new pool.
    pub fn new(runtime: Runtime, committee: Committee, round: u64) -> Self {
        let mut member_set = HashSet::new();
        let mut _worker_set = HashSet::new();

        for m in &committee.members {
            member_set.insert(m.public_key);
            if m.role == Role::Worker {
                _worker_set.insert(m.public_key);
            }
        }

        Pool {
            runtime,
            committee,
            round,
            execute_commitments: HashMap::new(),
            discrepancy: false,
            _next_timeout: 0,
            member_set,
            _worker_set,
        }
    }

    fn is_member(&self, id: &PublicKey) -> bool {
        self.member_set.contains(id)
    }

    fn _is_worker(&self, id: &PublicKey) -> bool {
        self._worker_set.contains(id)
    }

    fn is_scheduler(&self, id: &PublicKey) -> bool {
        if let Ok(scheduler) = self.committee.transaction_scheduler(self.round) {
            return &scheduler.public_key == id;
        }
        false
    }

    /// Verifies and adds a new executor commitment to the pool.
    fn add_verified_executor_commitment(
        &mut self,
        blk: &Block,
        nl: &impl NodeLookup,
        msg_validator: &impl MessageValidator,
        commit: ExecutorCommitment,
    ) -> Result<()> {
        if self.committee.kind != CommitteeKind::ComputeExecutor {
            return Err(Error::InvalidCommitteeKind.into());
        }

        // Ensure that the node is actually a committee member. We do not enforce specific
        // roles based on current discrepancy state to allow commitments arriving in any
        // order (e.g., a backup worker can submit a commitment even before there is a
        // discrepancy).
        if !self.is_member(&commit.node_id) {
            return Err(Error::NotInCommittee.into());
        }

        // Ensure the node did not already submit a commitment.
        if self.execute_commitments.contains_key(&commit.node_id) {
            return Err(Error::AlreadyCommitted.into());
        }

        if self.round != blk.header.round {
            return Err(Error::InvalidRound.into());
        }

        // Check if the block is based on the previous block.
        if !commit.header.header.is_parent_of(&blk.header) {
            return Err(Error::NotBasedOnCorrectBlock.into());
        }

        if commit.validate_basic().is_err() {
            return Err(Error::BadExecutorCommitment.into());
        }

        // TODO: Check for evidence of equivocation (oasis-core#3685).

        if !commit.is_indicating_failure() {
            // Verify RAK-attestation.
            if self.runtime.tee_hardware != TEEHardware::TEEHardwareInvalid {
                let n = nl.node(commit.node_id).map_err(|_|
                    // This should never happen as nodes cannot disappear mid-epoch.
                    Error::NotInCommittee)?;

                let ad = self
                    .runtime
                    .active_deployment(self.committee.valid_for)
                    .ok_or(
                        // This should never happen as we prevent this elsewhere.
                        Error::NoRuntime,
                    )?;

                let rt = n.get_runtime(&self.runtime.id, &ad.version).ok_or(
                    // We currently prevent this case throughout the rest of the system.
                    // Still, it's prudent to check.
                    Error::NotInCommittee,
                )?;

                let tee = rt.capabilities.tee.ok_or(
                    // This should never happen as we prevent this elsewhere.
                    Error::RakSigInvalid,
                )?;

                commit
                    .header
                    .verify_rak(tee.rak)
                    .map_err(|_| Error::RakSigInvalid)?;
            }

            // Check emitted runtime messages.
            match self.is_scheduler(&commit.node_id) {
                true => {
                    // The transaction scheduler can include messages.
                    if commit.messages.len() as u32 > self.runtime.executor.max_messages {
                        return Err(Error::InvalidMessages.into());
                    }

                    let messages_hash = commit
                        .header
                        .header
                        .messages_hash
                        .ok_or(Error::InvalidMessages)?;
                    let h = Message::messages_hash(&commit.messages);
                    if h != messages_hash {
                        return Err(Error::InvalidMessages.into());
                    }

                    // Perform custom message validation and propagate the error unchanged.
                    if !commit.messages.is_empty() {
                        msg_validator.validate(&commit.messages)?;
                    }
                }
                false => {
                    // Other workers cannot include any messages.
                    if !commit.messages.is_empty() {
                        return Err(Error::InvalidMessages.into());
                    }
                }
            }
        }

        self.execute_commitments.insert(commit.node_id, commit);

        Ok(())
    }

    /// Verifies and adds a new executor commitment to the pool.
    pub fn add_executor_commitment(
        &mut self,
        blk: &Block,
        nl: &impl NodeLookup,
        commit: ExecutorCommitment,
        msg_validator: &impl MessageValidator,
        chain_context: &String,
    ) -> Result<()> {
        // Check executor commitment signature.
        commit.verify(&self.runtime.id, chain_context)?;

        self.add_verified_executor_commitment(blk, nl, msg_validator, commit)
    }

    /// Performs a single round of commitment checks. If there are enough commitments
    /// in the pool, it performs discrepancy detection or resolution.
    pub fn process_commitments(&mut self, did_timeout: bool) -> Result<&dyn OpenCommitment> {
        if self.committee.kind != CommitteeKind::ComputeExecutor {
            panic!(
                "roothash/commitment: unknown committee kind: {:?}",
                self.committee.kind
            );
        }

        #[derive(Default)]
        struct Vote<'a> {
            commit: Option<&'a ExecutorCommitment>,
            tally: u16,
        }

        let mut total = 0;
        let mut commits = 0;
        let mut failures = 0;

        // Gather votes.
        let mut votes: HashMap<Hash, Vote> = HashMap::new();
        for n in &self.committee.members {
            if !self.discrepancy && n.role != Role::Worker {
                continue;
            }
            if self.discrepancy && n.role != Role::BackupWorker {
                continue;
            }

            total += 1;
            let commit = match self.execute_commitments.get(&n.public_key) {
                Some(commit) => commit,
                None => continue,
            };
            commits += 1;

            if commit.is_indicating_failure() {
                failures += 1;
                continue;
            }

            let k = commit.to_vote();
            match votes.get_mut(&k) {
                Some(v) => v.tally += 1,
                None => {
                    votes.insert(
                        k,
                        Vote {
                            tally: 1,
                            commit: Some(commit),
                        },
                    );
                }
            }

            if !self.discrepancy && votes.len() > 1 {
                self.discrepancy = true;
                return Err(Error::DiscrepancyDetected.into());
            }
        }

        // Determine whether the proposer has submitted a commitment.
        let proposer = self
            .committee
            .transaction_scheduler(self.round)
            .map_err(|_| Error::NoCommittee)?;
        let proposer_commit = self.execute_commitments.get(&proposer.public_key);
        if proposer_commit.is_none() && did_timeout {
            return Err(Error::NoProposerCommitment.into());
        }

        match self.discrepancy {
            false => {
                // Discrepancy detection.
                let allowed_stragglers = self.runtime.executor.allowed_stragglers;

                // If it is already known that the number of valid commitments will not exceed the required
                // threshold, there is no need to wait for the timer to expire. Instead, proceed directly to
                // the discrepancy resolution mode, regardless of any additional commits.
                if failures > allowed_stragglers {
                    self.discrepancy = true;
                    return Err(Error::DiscrepancyDetected.into());
                }

                // While a timer is running, all nodes are required to answer.
                let mut required = total;

                // After the timeout has elapsed, a limited number of stragglers are allowed.
                if did_timeout {
                    required -= allowed_stragglers;
                    commits -= failures // Since failures count as stragglers.
                }

                // Check if the majority has been reached.
                if commits < required || proposer_commit.is_none() {
                    return Err(Error::StillWaiting.into());
                }
            }
            true => {
                // Discrepancy resolution.
                let required = total / 2 + 1;

                // Find the commit with the highest number of votes.
                let mut top_vote = &Vote::default();
                for v in votes.values() {
                    if v.tally > top_vote.tally {
                        top_vote = v;
                    }
                }

                // Fail the round if the majority cannot be reached due to insufficient votes remaining
                // (e.g. too many nodes have failed),
                let remaining = total - commits;
                if top_vote.tally + remaining < required {
                    return Err(Error::InsufficientVotes.into());
                }

                // Check if the majority has been reached.
                if top_vote.tally < required || proposer_commit.is_none() {
                    if did_timeout {
                        return Err(Error::InsufficientVotes.into());
                    }
                    return Err(Error::StillWaiting.into());
                }

                let proposer_commit = proposer_commit.expect("proposer commit should be set");
                let top_vote_commit = top_vote.commit.expect("top vote commit should be set");

                // Make sure that the majority commitment is the same as the proposer commitment.
                if !proposer_commit.mostly_equal(top_vote_commit) {
                    return Err(Error::BadProposerCommitment.into());
                }
            }
        }

        // We must return the proposer commitment as that one contains additional data.
        let proposer_commit = proposer_commit.expect("proposer commit should be set");
        Ok(proposer_commit)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};

    use crate::{
        common::{
            crypto::{
                hash::Hash,
                signature::{self, PublicKey, Signature},
            },
            namespace::Namespace,
            versioned::Versioned,
        },
        consensus::{
            registry::{
                ExecutorParameters, Node, NodeRuntime, Runtime, RuntimeGovernanceModel,
                RuntimeKind, TEEHardware,
            },
            roothash::{
                Block, ComputeResultsHeader, Error, ExecutorCommitment, ExecutorCommitmentFailure,
                ExecutorCommitmentHeader, HeaderType, Message, Pool, RegistryMessage,
                StakingMessage,
            },
            scheduler::{Committee, CommitteeKind, CommitteeNode, Role},
            staking::Transfer,
        },
    };

    use super::NodeLookup;

    struct StaticNodeLookup {
        runtime: NodeRuntime,
    }

    impl NodeLookup for StaticNodeLookup {
        fn node(&self, id: PublicKey) -> Result<Node, Error> {
            Ok(Node {
                id,
                runtimes: Some(vec![self.runtime.clone()]),
                ..Default::default()
            })
        }
    }

    #[test]
    fn test_pool_single_commitment() {
        let chain_context = "test: oasis-core tests".to_owned();

        // Generate a non-TEE runtime.
        let id =
            Namespace::from("0000000000000000000000000000000000000000000000000000000000000000");

        let rt = Runtime {
            id,
            kind: RuntimeKind::KindCompute,
            tee_hardware: TEEHardware::TEEHardwareInvalid,
            executor: ExecutorParameters {
                max_messages: 32,
                ..Default::default()
            },
            governance_model: RuntimeGovernanceModel::GovernanceEntity,
            ..Default::default()
        };

        // Generate a commitment signing key.
        let sk = signature::PrivateKey::generate();

        // Generate a committee.
        let committee = Committee {
            kind: CommitteeKind::ComputeExecutor,
            members: vec![CommitteeNode {
                role: Role::Worker,
                public_key: sk.public_key(),
            }],
            runtime_id: id,
            valid_for: 0,
        };

        // Create a pool.
        let mut pool = Pool::new(rt, committee, 0);

        // Generate a commitment.
        let (child_blk, _, mut ec) = generate_executor_commitment(id, pool.round);

        let nl = StaticNodeLookup {
            runtime: NodeRuntime {
                id,
                ..Default::default()
            },
        };

        // Test invalid commitments.
        let tcs: Vec<(&str, fn(&mut ExecutorCommitment), Error)> = vec![
            (
                "BlockBadRound",
                |ec: &mut ExecutorCommitment| ec.header.header.round -= 1,
                Error::NotBasedOnCorrectBlock,
            ),
            (
                "BlockBadPreviousHash",
                |ec: &mut ExecutorCommitment| {
                    ec.header.header.previous_hash = Hash::digest_bytes(b"invalid")
                },
                Error::NotBasedOnCorrectBlock,
            ),
            (
                "MissingIORootHash",
                |ec: &mut ExecutorCommitment| ec.header.header.io_root = None,
                Error::BadExecutorCommitment,
            ),
            (
                "MissingStateRootHash",
                |ec: &mut ExecutorCommitment| ec.header.header.state_root = None,
                Error::BadExecutorCommitment,
            ),
            (
                "MissingMessagesHash",
                |ec: &mut ExecutorCommitment| ec.header.header.messages_hash = None,
                Error::BadExecutorCommitment,
            ),
            (
                "MissingInMessagesHash",
                |ec: &mut ExecutorCommitment| ec.header.header.in_msgs_hash = None,
                Error::BadExecutorCommitment,
            ),
            (
                "BadFailureIndicating",
                |ec: &mut ExecutorCommitment| {
                    ec.header.failure = ExecutorCommitmentFailure::FailureUnknown
                },
                Error::BadExecutorCommitment,
            ),
        ];

        let msg_validator = |_: &_| Ok(());
        for (name, f, expected_err) in tcs {
            let (_, _, mut invalid_ec) = generate_executor_commitment(id, pool.round);
            f(&mut invalid_ec);

            invalid_ec.node_id = sk.public_key();
            let res = invalid_ec.sign(&sk, &id, &chain_context);
            assert!(res.is_ok(), "invalid_ec.sign({})", name);

            let res = pool.add_executor_commitment(
                &child_blk,
                &nl,
                invalid_ec,
                &msg_validator,
                &chain_context,
            );
            assert!(res.is_err(), "add_executor_commitment({})", name);
            assert_eq!(
                res.err().unwrap().to_string(),
                expected_err.to_string(),
                "add_executor_commitment({})",
                name
            );
        }

        // Generate a valid commitment.
        ec.node_id = sk.public_key();
        let res = ec.sign(&sk, &id, &chain_context);
        assert!(res.is_ok(), "ec.sign");

        // There should not be enough executor commitments.
        let res = pool.process_commitments(false);
        assert_eq!(
            res.err().unwrap().to_string(),
            Error::StillWaiting.to_string(),
            "process_commitments",
        );

        let res = pool.process_commitments(true);
        assert_eq!(
            res.err().unwrap().to_string(),
            Error::NoProposerCommitment.to_string(),
            "process_commitments",
        );

        // Test message validator function.
        let mut ec_with_msgs = ec.clone();
        ec_with_msgs.messages = vec![
            Message::Staking(Versioned {
                version: 0,
                inner: StakingMessage::Transfer(Transfer::default()),
            }),
            Message::Registry(Versioned {
                version: 0,
                inner: RegistryMessage::UpdateRuntime(Runtime::default()),
            }),
        ];
        let msg_hash = Message::messages_hash(&ec_with_msgs.messages);
        ec_with_msgs.header.header.messages_hash = Some(msg_hash);

        let res = ec_with_msgs.sign(&sk, &id, &chain_context);
        assert!(res.is_ok(), "ec_with_msgs.sign");

        let error_msg = "message validation error";
        let always_fail_msg_validator = |_: &_| -> Result<()> { Err(anyhow!(error_msg)) };
        let res = pool.add_executor_commitment(
            &child_blk,
            &nl,
            ec_with_msgs,
            &always_fail_msg_validator,
            &chain_context,
        );
        assert!(res.is_err(), "add_executor_commitment");
        assert_eq!(
            res.err().unwrap().to_string(),
            error_msg,
            "add_executor_commitment",
        );

        // Adding a commitment should succeed.
        let res = pool.add_executor_commitment(
            &child_blk,
            &nl,
            ec.clone(),
            &msg_validator,
            &chain_context,
        );
        assert!(res.is_ok(), "add_executor_commitment");

        // Adding a commitment twice for the same node should fail.
        let res = pool.add_executor_commitment(
            &child_blk,
            &nl,
            ec.clone(),
            &msg_validator,
            &chain_context,
        );
        assert!(res.is_err(), "add_executor_commitment, duplicate");

        // There should be enough executor commitments and no discrepancy.
        let res = pool.process_commitments(false);
        assert!(res.is_ok(), "process_commitments");
        let dd_ec = res
            .unwrap()
            .to_dd_result()
            .downcast_ref::<ExecutorCommitment>();
        assert_eq!(dd_ec, Some(&ec), "DD should return the correct commitment");
        assert_eq!(false, pool.discrepancy);
    }

    fn generate_executor_commitment(
        id: Namespace,
        round: u64,
    ) -> (Block, Block, ExecutorCommitment) {
        let child_blk = Block::new_genesis_block(id, round);
        let parent_blk = Block::new_empty_block(&child_blk, 1, HeaderType::Normal);

        // TODO: Add tests with some emitted messages.
        let msgs_hash = Message::messages_hash(&vec![]);
        // TODO: Add tests with some incoming messages.
        let in_msgs_hash = Message::in_messages_hash(&vec![]);

        let ec = ExecutorCommitment {
            header: ExecutorCommitmentHeader {
                header: ComputeResultsHeader {
                    round: parent_blk.header.round,
                    previous_hash: parent_blk.header.previous_hash,
                    io_root: Some(parent_blk.header.io_root),
                    state_root: Some(parent_blk.header.state_root),
                    messages_hash: Some(msgs_hash),
                    in_msgs_hash: Some(in_msgs_hash),
                    in_msgs_count: 0,
                },
                failure: ExecutorCommitmentFailure::FailureNone,
                rak_signature: None,
            },
            node_id: PublicKey::default(),
            signature: Signature::default(),
            messages: vec![],
        };

        (child_blk, parent_blk, ec)
    }
}
