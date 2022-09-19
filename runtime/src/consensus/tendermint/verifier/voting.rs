use std::{collections::HashSet, convert::TryFrom};

use tendermint::{
    block::CommitSig,
    vote::{SignedVote, ValidatorIndex, Vote},
};
use tendermint_light_client::{
    operations::{VotingPowerCalculator, VotingPowerTally},
    types::{Commit, SignedHeader, TrustThreshold, ValidatorSet},
    verifier::errors::VerificationError,
};

use crate::{common::crypto::hash::Hash, consensus::tendermint::TENDERMINT_CONTEXT};

// Voting power calculator which uses Oasis Core's domain separation for verifying signatures.
pub struct DomSepVotingPowerCalculator;

impl VotingPowerCalculator for DomSepVotingPowerCalculator {
    fn voting_power_in(
        &self,
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
        trust_threshold: TrustThreshold,
    ) -> Result<VotingPowerTally, VerificationError> {
        let signatures = &signed_header.commit.signatures;

        let mut tallied_voting_power = 0_u64;
        let mut seen_validators = HashSet::new();

        // Get non-absent votes from the signatures
        let non_absent_votes = signatures.iter().enumerate().flat_map(|(idx, signature)| {
            non_absent_vote(
                signature,
                ValidatorIndex::try_from(idx).unwrap(),
                &signed_header.commit,
            )
            .map(|vote| (signature, vote))
        });

        for (signature, vote) in non_absent_votes {
            // Ensure we only count a validator's power once
            if seen_validators.contains(&vote.validator_address) {
                return Err(VerificationError::duplicate_validator(
                    vote.validator_address,
                ));
            } else {
                seen_validators.insert(vote.validator_address);
            }

            let validator = match validator_set.validator(vote.validator_address) {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            };

            let signed_vote =
                SignedVote::from_vote(vote.clone(), signed_header.header.chain_id.clone())
                    .ok_or_else(VerificationError::missing_signature)?;

            // Check vote is valid
            let sign_bytes = signed_vote.sign_bytes();
            // Use Oasis Core domain separation scheme.
            let sign_bytes = Hash::digest_bytes_list(&[TENDERMINT_CONTEXT, &sign_bytes]);
            let power = validator.power();
            validator
                .verify_signature(sign_bytes.as_ref(), signed_vote.signature())
                .map_err(|_| {
                    VerificationError::invalid_signature(
                        signed_vote.signature().as_bytes().to_vec(),
                        Box::new(validator),
                        sign_bytes.as_ref().into(),
                    )
                })?;

            // If the vote is neither absent nor nil, tally its power
            if signature.is_commit() {
                tallied_voting_power += power;
            } else {
                // It's OK. We include stray signatures (~votes for nil)
                // to measure validator availability.
            }

            // TODO: Break out of the loop when we have enough voting power.
            // See https://github.com/informalsystems/tendermint-rs/issues/235
        }

        let voting_power = VotingPowerTally {
            total: self.total_power_of(validator_set),
            tallied: tallied_voting_power,
            trust_threshold,
        };

        Ok(voting_power)
    }
}

// Copied from tendermint-rs as it is not public.
fn non_absent_vote(
    commit_sig: &CommitSig,
    validator_index: ValidatorIndex,
    commit: &Commit,
) -> Option<Vote> {
    let (validator_address, timestamp, signature, block_id) = match commit_sig {
        CommitSig::BlockIdFlagAbsent { .. } => return None,
        CommitSig::BlockIdFlagCommit {
            validator_address,
            timestamp,
            signature,
        } => (
            *validator_address,
            *timestamp,
            signature,
            Some(commit.block_id),
        ),
        CommitSig::BlockIdFlagNil {
            validator_address,
            timestamp,
            signature,
        } => (*validator_address, *timestamp, signature, None),
    };

    Some(Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: commit.height,
        round: commit.round,
        block_id,
        timestamp: Some(timestamp),
        validator_address,
        validator_index,
        signature: signature.clone(),
    })
}
