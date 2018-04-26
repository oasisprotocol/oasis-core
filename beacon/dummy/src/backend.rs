use byteorder::{LittleEndian, WriteBytesExt};
use ekiden_beacon_base::RandomBeacon;
use ekiden_common::bytes::B256;
use ekiden_common::epochtime::EpochTime;
use ekiden_common::futures::{future, BoxFuture};
use ekiden_common::ring::digest;

const DUMMY_BEACON_CONTEXT: &'static [u8] = b"EkB-Dumm";

/// Dummy RandomBeacon implementation.
///
/// WARNING: As the name suggests, this implementation is intended for testing
/// purposes and is INSECURE due to the returned values being entirely
/// deterministic.
pub struct InsecureDummyRandomBeacon;

impl RandomBeacon for InsecureDummyRandomBeacon {
    fn get_beacon(&self, epoch: EpochTime) -> BoxFuture<B256> {
        // Simulate a per-epoch shared random beacon value with
        // `SHA512_256("EkB-Dumm" | to_le_64(epoch))` as it is a reasonable
        // approximation of a well behaved random beacon, just without the
        // randomness.
        let mut seed = Vec::with_capacity(DUMMY_BEACON_CONTEXT.len() + 8);
        seed.extend_from_slice(DUMMY_BEACON_CONTEXT);
        seed.write_u64::<LittleEndian>(epoch).unwrap();

        Box::new(future::ok(B256::from(
            digest::digest(&digest::SHA512_256, &seed).as_ref(),
        )))
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_hex;

    use self::rustc_hex::ToHex;
    use super::*;
    use ekiden_common::futures::Future;

    #[test]
    fn test_insecure_dummy_random_beacon() {
        let beacon = InsecureDummyRandomBeacon {};

        // Trivial known answer tests, generated with a Go implementation of
        // the same algorithm.
        let v = &(beacon.get_beacon(0).wait()).unwrap();
        assert_eq!(
            (*v).to_hex(),
            "0c2d4edf3c57c2071f8856d1f74cb126455c2df949a2e3638509b20f8bd5e85d"
        );

        let v = &(beacon.get_beacon(0xcafebabedeadbeef).wait()).unwrap();
        assert_eq!(
            (*v).to_hex(),
            "36ae91d1c4c40e52bcaa86f5cbb8fe514f36e5165c721b18f5feabc25fb0aa84"
        );
    }
}
