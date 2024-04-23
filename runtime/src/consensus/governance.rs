//! Governance structures.
//!
//! # Note
//!
//! This **MUST** be kept in sync with go/governance/api.
//!
use std::collections::BTreeMap;

use crate::{
    common::{quantity::Quantity, version::ProtocolVersions},
    consensus::beacon::EpochTime,
};

/// A governance vote.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, cbor::Encode, cbor::Decode,
)]
#[repr(u8)]
pub enum Vote {
    /// Invalid vote that should never be explicitly set.
    #[default]
    Invalid = 0,
    /// Yes Vote.
    Yes = 1,
    /// No vote.
    No = 2,
    /// Abstained.
    Abstain = 3,
}

/// Vote for a proposal.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ProposalVote {
    /// Unique identifier of a proposal.
    pub id: u64,

    /// Proposal vote.
    pub vote: Vote,
}

/// Upgrade proposal content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct UpgradeProposal {
    pub v: u16,
    pub handler: String,
    pub target: ProtocolVersions,
    pub epoch: EpochTime,
}

/// Cancel proposal content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct CancelUpgradeProposal {
    pub proposal_id: u64,
}

/// Change parameters proposal content.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ChangeParametersProposal {
    pub module: String,
    pub changes: Option<cbor::Value>,
}

/// Consensus layer governance proposal content.
#[derive(Clone, Debug, Default, PartialEq, Eq, cbor::Encode, cbor::Decode)]
pub struct ProposalContent {
    #[cbor(optional)]
    pub upgrade: Option<UpgradeProposal>,
    #[cbor(optional)]
    pub cancel_upgrade: Option<CancelUpgradeProposal>,
    #[cbor(optional)]
    pub change_parameters: Option<ChangeParametersProposal>,
}

// Allowed governance consensus parameter changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, cbor::Encode, cbor::Decode)]
pub struct ConsensusParameterChanges {
    #[cbor(optional)]
    pub gas_costs: BTreeMap<String, u64>,
    #[cbor(optional)]
    pub min_proposal_deposit: Option<Quantity>,
    #[cbor(optional)]
    pub voting_period: Option<EpochTime>,
    #[cbor(optional)]
    pub stake_threshold: Option<u8>,
    #[cbor(optional)]
    pub upgrade_min_epoch_diff: Option<EpochTime>,
    #[cbor(optional)]
    pub upgrade_cancel_min_epoch_diff: Option<EpochTime>,
    #[cbor(optional)]
    pub enable_change_parameters_proposal: Option<bool>,
}

#[cfg(test)]
mod tests {
    use base64::prelude::*;

    use super::*;

    #[test]
    fn test_consistent_proposal_vote() {
        // NOTE: These tests MUST be synced with go/governance/api/api_test.go.
        let tcs = vec![
            (
                "omJpZAtkdm90ZQE=",
                ProposalVote {
                    id: 11,
                    vote: Vote::Yes,
                },
            ),
            (
                "omJpZAxkdm90ZQI=",
                ProposalVote {
                    id: 12,
                    vote: Vote::No,
                },
            ),
            (
                "omJpZA1kdm90ZQM=",
                ProposalVote {
                    id: 13,
                    vote: Vote::Abstain,
                },
            ),
        ];
        for (encoded_base64, vote) in tcs {
            let dec: ProposalVote =
                cbor::from_slice(&BASE64_STANDARD.decode(encoded_base64).unwrap())
                    .expect("proposal vote should deserialize correctly");
            assert_eq!(
                dec, vote,
                "decoded proposal vote should match the expected value"
            );

            let ser = BASE64_STANDARD.encode(cbor::to_vec(dec));
            assert_eq!(
                ser, encoded_base64,
                "proposal vote should serialize correctly"
            );
        }
    }

    #[test]
    fn test_consistent_proposal_content() {
        // NOTE: These tests MUST be synced with go/governance/api/api_test.go.
        let tcs = vec![
            (
                "oW5jYW5jZWxfdXBncmFkZaFrcHJvcG9zYWxfaWQYKg==",
                ProposalContent {
                    cancel_upgrade: Some(CancelUpgradeProposal { proposal_id: 42 }),
                    ..Default::default()
                },
            ),
            (
                "oWd1cGdyYWRlpGF2AmVlcG9jaBgqZnRhcmdldKNyY29uc2Vuc3VzX3Byb3RvY29soWVwYXRjaBh7dXJ1bnRpbWVfaG9zdF9wcm90b2NvbKFlcGF0Y2gZAch4GnJ1bnRpbWVfY29tbWl0dGVlX3Byb3RvY29soWVwYXRjaBkDFWdoYW5kbGVybHRlc3QtaGFuZGxlcg==",
                ProposalContent {
                    upgrade: Some(UpgradeProposal {
                        v: 2,
                        handler: "test-handler".into(),
                        target: ProtocolVersions { consensus_protocol: 123.into(), runtime_host_protocol: 456.into(), runtime_committee_protocol: 789.into() } ,
                        epoch: 42,
                    }),
                    ..Default::default()
                },
            ),
            (
                "oXFjaGFuZ2VfcGFyYW1ldGVyc6JmbW9kdWxla3Rlc3QtbW9kdWxlZ2NoYW5nZXOhbXZvdGluZ19wZXJpb2QYew==",
                ProposalContent {
                    change_parameters: Some(ChangeParametersProposal {
                        module: "test-module".into(),
                        changes: Some(cbor::to_value(ConsensusParameterChanges{
                            voting_period: Some(123),
                            ..Default::default()
                        })),
                     }),
                    ..Default::default()
                }
            ),
        ];
        for (encoded_base64, content) in tcs {
            let dec: ProposalContent =
                cbor::from_slice(&BASE64_STANDARD.decode(encoded_base64).unwrap())
                    .expect("proposal content should deserialize correctly");
            assert_eq!(
                dec, content,
                "decoded proposal content should match the expected value"
            );

            let ser = BASE64_STANDARD.encode(cbor::to_vec(dec));
            assert_eq!(
                ser, encoded_base64,
                "proposal content should serialize correctly"
            );
        }
    }
}
