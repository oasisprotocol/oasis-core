use anyhow::Result;

use crate::{
    common::{crypto::hash::Hash, quantity::Quantity, versioned::Versioned},
    consensus::{address::Address, governance, registry, staking},
};

/// A message that can be emitted by the runtime to be processed by the consensus layer.
#[derive(Clone, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub enum Message {
    #[cbor(rename = "staking")]
    Staking(Versioned<StakingMessage>),

    #[cbor(rename = "registry")]
    Registry(Versioned<RegistryMessage>),

    #[cbor(rename = "governance")]
    Governance(Versioned<GovernanceMessage>),
}

impl Message {
    /// Returns a hash of provided runtime messages.
    pub fn messages_hash(msgs: &[Message]) -> Hash {
        if msgs.is_empty() {
            // Special case if there are no messages.
            return Hash::empty_hash();
        }
        Hash::digest_bytes(&cbor::to_vec(msgs.to_vec()))
    }

    /// Returns a hash of provided incoming runtime messages.
    pub fn in_messages_hash(msgs: &[IncomingMessage]) -> Hash {
        if msgs.is_empty() {
            // Special case if there are no messages.
            return Hash::empty_hash();
        }
        Hash::digest_bytes(&cbor::to_vec(msgs.to_vec()))
    }

    /// Performs basic validation of the runtime message.
    pub fn validate_basic(&self) -> Result<()> {
        match self {
            Message::Staking(msg) => msg.inner.validate_basic(),
            Message::Registry(msg) => msg.inner.validate_basic(),
            Message::Governance(msg) => msg.inner.validate_basic(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub enum StakingMessage {
    #[cbor(rename = "transfer")]
    Transfer(staking::Transfer),

    #[cbor(rename = "withdraw")]
    Withdraw(staking::Withdraw),

    #[cbor(rename = "add_escrow")]
    AddEscrow(staking::Escrow),

    #[cbor(rename = "reclaim_escrow")]
    ReclaimEscrow(staking::ReclaimEscrow),
}

impl StakingMessage {
    /// Performs basic validation of the staking message.
    pub fn validate_basic(&self) -> Result<()> {
        match self {
            StakingMessage::Transfer(_) => {
                // No validation at this time.
                Ok(())
            }
            StakingMessage::Withdraw(_) => {
                // No validation at this time.
                Ok(())
            }
            StakingMessage::AddEscrow(_) => {
                // No validation at this time.
                Ok(())
            }
            StakingMessage::ReclaimEscrow(_) => {
                // No validation at this time.
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub enum RegistryMessage {
    #[cbor(rename = "update_runtime")]
    UpdateRuntime(registry::Runtime),
}

impl RegistryMessage {
    /// Performs basic validation of the registry message.
    pub fn validate_basic(&self) -> Result<()> {
        match self {
            RegistryMessage::UpdateRuntime(_) => {
                // The runtime descriptor will already be validated in registerRuntime
                // in the registry app when it processes the message, so we don't have
                // to do any validation here.
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub enum GovernanceMessage {
    #[cbor(rename = "cast_vote")]
    CastVote(governance::ProposalVote),
    #[cbor(rename = "submit_proposal")]
    SubmitProposal(governance::ProposalContent),
}

impl GovernanceMessage {
    /// Performs basic validation of the governance message.
    pub fn validate_basic(&self) -> Result<()> {
        match self {
            GovernanceMessage::CastVote(_) => {
                // No validation at this time.
                Ok(())
            }
            GovernanceMessage::SubmitProposal(_) => {
                // No validation at this time.
                Ok(())
            }
        }
    }
}

/// An incoming message emitted by the consensus layer to be processed by the runtime.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct IncomingMessage {
    /// Unique identifier of the message.
    pub id: u64,
    /// Address of the caller authenticated by the consensus layer.
    pub caller: Address,
    /// An optional tag provided by the caller which is ignored and can be used to match processed
    /// incoming message events later.
    #[cbor(optional)]
    pub tag: u64,
    /// Fee sent into the runtime as part of the message being sent. The fee is transferred before
    /// the message is processed by the runtime.
    #[cbor(optional)]
    pub fee: Quantity,
    /// Tokens sent into the runtime as part of the message being sent. The tokens are transferred
    /// before the message is processed by the runtime.
    #[cbor(optional)]
    pub tokens: Quantity,
    /// Arbitrary runtime-dependent data.
    #[cbor(optional)]
    pub data: Vec<u8>,
}

impl IncomingMessage {
    /// Returns a hash of provided runtime messages.
    pub fn in_messages_hash(msgs: &[IncomingMessage]) -> Hash {
        if msgs.is_empty() {
            // Special case if there are no messages.
            return Hash::empty_hash();
        }
        Hash::digest_bytes(&cbor::to_vec(msgs.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        common::{
            crypto::{hash::Hash, signature::PublicKey},
            namespace::Namespace,
            quantity,
            versioned::Versioned,
        },
        consensus::{governance, registry, scheduler, staking},
    };

    use super::*;

    #[test]
    fn test_consistent_messages_hash() {
        // NOTE: This runtime structure must be synced with go/roothash/api/messages_test.go.
        let test_ent_id =
            PublicKey::from("4ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35");

        let q = quantity::Quantity::from(1000u32);

        let mut st = BTreeMap::new();
        st.insert(staking::ThresholdKind::KindNodeCompute, q.clone());

        let mut wlc = BTreeMap::new();
        wlc.insert(registry::RolesMask::ROLE_COMPUTE_WORKER, 2);

        let mut wl = BTreeMap::new();
        wl.insert(
            test_ent_id,
            registry::EntityWhitelistConfig { max_nodes: wlc },
        );

        let rt = registry::Runtime {
            v: registry::LATEST_RUNTIME_DESCRIPTOR_VERSION,
            id: Namespace::default(),
            entity_id: test_ent_id,
            genesis: registry::RuntimeGenesis {
                state_root: Hash::empty_hash(),
                round: 0,
            },
            kind: registry::RuntimeKind::KindCompute,
            tee_hardware: registry::TEEHardware::TEEHardwareInvalid,
            deployments: vec![registry::VersionInfo::default()],
            key_manager: None,
            executor: registry::ExecutorParameters {
                group_size: 3,
                group_backup_size: 5,
                allowed_stragglers: 1,
                round_timeout: 10,
                max_messages: 32,
                ..Default::default()
            },
            txn_scheduler: registry::TxnSchedulerParameters {
                batch_flush_timeout: 20000000000, // 20 seconds.
                max_batch_size: 1,
                max_batch_size_bytes: 1024,
                max_in_messages: 0,
                propose_batch_timeout: 5,
            },
            storage: registry::StorageParameters {
                checkpoint_interval: 0,
                checkpoint_num_kept: 0,
                checkpoint_chunk_size: 0,
            },
            admission_policy: registry::RuntimeAdmissionPolicy::EntityWhitelist(
                registry::EntityWhitelistRuntimeAdmissionPolicy { entities: wl },
            ),
            constraints: {
                let mut cs = BTreeMap::new();
                cs.insert(scheduler::CommitteeKind::ComputeExecutor, {
                    let mut ce = BTreeMap::new();
                    ce.insert(
                        scheduler::Role::Worker,
                        registry::SchedulingConstraints {
                            min_pool_size: Some(registry::MinPoolSizeConstraint { limit: 1 }),
                            validator_set: Some(registry::ValidatorSetConstraint {}),
                            ..Default::default()
                        },
                    );
                    ce.insert(
                        scheduler::Role::BackupWorker,
                        registry::SchedulingConstraints {
                            min_pool_size: Some(registry::MinPoolSizeConstraint { limit: 2 }),
                            ..Default::default()
                        },
                    );
                    ce
                });

                cs
            },
            staking: registry::RuntimeStakingParameters {
                thresholds: st,
                ..Default::default()
            },
            governance_model: registry::RuntimeGovernanceModel::GovernanceEntity,
        };

        // NOTE: These hashes MUST be synced with go/roothash/api/message/message_test.go.
        let tcs = vec![
            (
                vec![],
                "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::Transfer(staking::Transfer::default()),
                ))],
                "a6b91f974b34a9192efd12025659a768520d2f04e1dae9839677456412cdb2be",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::Withdraw(staking::Withdraw::default()),
                ))],
                "069b0fda76d804e3fd65d4bbd875c646f15798fb573ac613100df67f5ba4c3fd",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::AddEscrow(staking::Escrow::default()),
                ))],
                "65049870b9dae657390e44065df0c78176816876e67b96dac7791ee6a1aa42e2",
            ),
            (
                vec![Message::Staking(Versioned::new(
                    0,
                    StakingMessage::ReclaimEscrow(staking::ReclaimEscrow::default()),
                ))],
                "c78547eae2f104268e49827cbe624cf2b350ee59e8d693dec0673a70a4664a2e",
            ),
            (
                vec![Message::Registry(Versioned::new(
                    0,
                    RegistryMessage::UpdateRuntime(registry::Runtime::default()),
                ))],
                "ac8ff938607f234f0db60dc2e81897f50c3918cc51998c633a0f3f2b98374db1",
            ),
            (
                vec![Message::Registry(Versioned::new(
                    0,
                    RegistryMessage::UpdateRuntime(rt),
                ))],
                "67da1da17b12c398d4dec165480df73c244740f8fb876f59a76cd29e30056b6d",
            ),
            (
                vec![Message::Governance(Versioned::new(
                    0,
                    GovernanceMessage::CastVote(governance::ProposalVote {
                        id: 32,
                        vote: governance::Vote::Yes,
                    }),
                ))],
                "f45e26eb8ace807ad5bd02966cde1f012d1d978d4cbddd59e9bfd742dcf39b90",
            ),
            (
                vec![Message::Governance(Versioned::new(
                    0,
                    GovernanceMessage::SubmitProposal(governance::ProposalContent {
                        cancel_upgrade: Some(governance::CancelUpgradeProposal { proposal_id: 32 }),
                        ..Default::default()
                    }),
                ))],
                "03312ddb5c41a30fbd29fb91cf6bf26d58073996f89657ca4f3b3a43a98bfd0b",
            ),
        ];
        for (msgs, expected_hash) in tcs {
            println!("{:?}", cbor::to_vec(msgs.clone()));
            assert_eq!(Message::messages_hash(&msgs), Hash::from(expected_hash));
        }
    }
}
