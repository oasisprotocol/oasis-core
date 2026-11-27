use anyhow::anyhow;

use crate::{
    common::namespace::Namespace,
    consensus::{
        beacon::EpochTime,
        roothash::Header,
        state::{
            beacon::ImmutableState as BeaconState, roothash::ImmutableState as RoothashState,
            ConsensusState,
        },
        tendermint::{verifier::Cache, LightBlockMeta},
        verifier::Error,
        LightBlock,
    },
};

/// Verifies that the namespace in the runtime header matches the trusted namespace.
pub fn verify_namespace(trusted: Namespace, runtime_header: &Header) -> Result<(), Error> {
    if trusted != runtime_header.namespace {
        return Err(Error::VerificationFailed(anyhow!(
            "header namespace does not match trusted runtime id"
        )));
    }

    Ok(())
}

/// Verifies that consensus height has correctly advanced since the last update.
pub fn verify_consensus_advance(cache: &Cache, consensus_block: &LightBlock) -> Result<(), Error> {
    if consensus_block.height < cache.last_verified_height {
        // Reject requests for earlier heights.
        return Err(Error::VerificationFailed(anyhow!(
            "height seems to have moved backwards"
        )));
    }

    Ok(())
}

/// Verifies that the round has correctly advanced since the last update.
pub fn verify_round_advance(
    cache: &Cache,
    runtime_header: &Header,
    consensus_block: &LightBlock,
    epoch: EpochTime,
) -> Result<(), Error> {
    if runtime_header.round < cache.last_verified_round {
        // Reject requests for earlier rounds.
        return Err(Error::VerificationFailed(anyhow!(
            "round seems to have moved backwards"
        )));
    }
    if epoch < cache.last_verified_epoch {
        // Reject requests for earlier epochs.
        return Err(Error::VerificationFailed(anyhow!(
            "epoch seems to have moved backwards"
        )));
    }

    // If round has advanced make sure that consensus height has also advanced as a round can
    // only be finalized in a subsequent consensus block. This is to avoid a situation where
    // one would keep feeding the same consensus block for subsequent rounds.
    if runtime_header.round > cache.last_verified_round
        && consensus_block.height <= cache.last_verified_height
    {
        return Err(Error::VerificationFailed(anyhow!(
            "consensus height did not advance but runtime round did"
        )));
    }

    Ok(())
}

/// Verifies that the runtime header has time consistent with the consensus header.
pub fn verify_time(runtime_header: &Header, consensus_block: &LightBlockMeta) -> Result<(), Error> {
    let consensus_header = &consensus_block
        .signed_header
        .as_ref()
        .ok_or_else(|| Error::VerificationFailed(anyhow!("missing signed header")))?
        .header;
    if runtime_header.timestamp != consensus_header.time.unix_timestamp() as u64 {
        return Err(Error::VerificationFailed(anyhow!(
            "runtime block timestamp inconsistent with consensus time"
        )));
    }

    Ok(())
}

/// Verifies that the runtime header is consistent with consensus state.
///
/// Assumes the namespace in the runtime header has already been verified via `verify_namespace`.
pub fn verify_runtime_header(state: &ConsensusState, runtime_header: &Header) -> Result<(), Error> {
    let roothash_state = RoothashState::new(&state);
    let runtime_state = roothash_state
        .runtime_state(runtime_header.namespace)
        .map_err(|err| {
            Error::VerificationFailed(anyhow!("failed to retrieve runtime state: {}", err))
        })?;

    if *runtime_header != runtime_state.last_block.header {
        return Err(Error::VerificationFailed(anyhow!(
            "runtime header mismatch (expected: {} got: {})",
            runtime_state.last_block.header.encoded_hash(),
            runtime_header.encoded_hash(),
        )));
    }

    Ok(())
}

/// Verifies that the epoch is consistent with consensus state.
pub fn verify_epoch(state: &ConsensusState, epoch: EpochTime) -> Result<(), Error> {
    let beacon_state = BeaconState::new(&state);
    let current_epoch = beacon_state
        .epoch()
        .map_err(|err| Error::VerificationFailed(anyhow!("failed to retrieve epoch: {}", err)))?;

    if current_epoch != epoch {
        return Err(Error::VerificationFailed(anyhow!(
            "epoch number mismatch (expected: {} got: {})",
            current_epoch,
            epoch,
        )));
    }

    Ok(())
}
