//! Helper methods for packing and unpacking data.
use std::convert::TryInto;

use oasis_core_runtime::{
    common::{
        crypto::mrae::{
            deoxysii::TAG_SIZE,
            nonce::{Nonce, NONCE_SIZE},
        },
        namespace::{Namespace, NAMESPACE_SIZE},
    },
    consensus::beacon::EpochTime,
};

use super::SECRET_SIZE;

/// The size of the epoch in bytes.
const EPOCH_SIZE: usize = 8;
/// The size of the generation in bytes.
const GENERATION_SIZE: usize = 8;
/// The size of an encrypted secret.
const SECRET_STORAGE_SIZE: usize = SECRET_SIZE + TAG_SIZE + NONCE_SIZE;

/// Concatenate runtime ID and epoch (runtime_id || epoch)
/// into a byte vector using little-endian byte order.
pub fn pack_runtime_id_epoch(runtime_id: &Namespace, epoch: EpochTime) -> Vec<u8> {
    let mut additional_data = runtime_id.0.to_vec();
    additional_data.extend(epoch.to_le_bytes());
    additional_data
}

/// Unpack the concatenation of runtime ID and epoch (runtime_id || epoch).
pub fn unpack_runtime_id_epoch(data: Vec<u8>) -> Option<(Namespace, EpochTime)> {
    if data.len() != NAMESPACE_SIZE + EPOCH_SIZE {
        return None;
    }

    let runtime_id: Namespace = data
        .get(0..NAMESPACE_SIZE)
        .unwrap()
        .try_into()
        .expect("slice with incorrect length");

    let epoch = u64::from_le_bytes(
        data.get(NAMESPACE_SIZE..)
            .unwrap()
            .try_into()
            .expect("slice with incorrect length"),
    );

    Some((runtime_id, epoch))
}

/// Concatenate runtime ID and generation (runtime_id || generation)
/// into a byte vector using little-endian byte order.
pub fn pack_runtime_id_generation(runtime_id: &Namespace, generation: u64) -> Vec<u8> {
    let mut data = runtime_id.0.to_vec();
    data.extend(generation.to_le_bytes());
    data
}

/// Unpack the concatenation of runtime ID and generation (runtime_id || generation).
pub fn unpack_runtime_id_generation(data: Vec<u8>) -> Option<(Namespace, u64)> {
    if data.len() != NAMESPACE_SIZE + GENERATION_SIZE {
        return None;
    }

    let runtime_id: Namespace = data
        .get(0..NAMESPACE_SIZE)
        .unwrap()
        .try_into()
        .expect("slice with incorrect length");

    let generation = u64::from_le_bytes(
        data.get(NAMESPACE_SIZE..)
            .unwrap()
            .try_into()
            .expect("slice with incorrect length"),
    );

    Some((runtime_id, generation))
}

/// Concatenate runtime ID, generation and epoch (runtime_id || generation || epoch)
/// into a byte vector using little-endian byte order.
pub fn pack_runtime_id_generation_epoch(
    runtime_id: &Namespace,
    generation: u64,
    epoch: EpochTime,
) -> Vec<u8> {
    let mut additional_data = runtime_id.0.to_vec();
    additional_data.extend(generation.to_le_bytes());
    additional_data.extend(epoch.to_le_bytes());
    additional_data
}

/// Unpack the concatenation of runtime ID, generation and epoch (runtime_id || generation || epoch).
pub fn unpack_runtime_id_generation_epoch(data: Vec<u8>) -> Option<(Namespace, u64, EpochTime)> {
    if data.len() != NAMESPACE_SIZE + GENERATION_SIZE + EPOCH_SIZE {
        return None;
    }

    let runtime_id: Namespace = data
        .get(0..NAMESPACE_SIZE)
        .unwrap()
        .try_into()
        .expect("slice with incorrect length");

    let generation = u64::from_le_bytes(
        data.get(NAMESPACE_SIZE..NAMESPACE_SIZE + GENERATION_SIZE)
            .unwrap()
            .try_into()
            .expect("slice with incorrect length"),
    );

    let epoch = u64::from_le_bytes(
        data.get(NAMESPACE_SIZE + GENERATION_SIZE..)
            .unwrap()
            .try_into()
            .expect("slice with incorrect length"),
    );

    Some((runtime_id, generation, epoch))
}

/// Concatenate ciphertext and nonce (ciphertext || nonce) into a byte vector.
pub fn pack_ciphertext_nonce(ciphertext: &Vec<u8>, nonce: &Nonce) -> Vec<u8> {
    let mut data = ciphertext.clone();
    data.extend_from_slice(&nonce.to_vec());
    data
}

/// Unpack the concatenation of encrypted secret and nonce (ciphertext || nonce).
pub fn unpack_encrypted_secret_nonce(data: &Vec<u8>) -> Option<(Vec<u8>, [u8; NONCE_SIZE])> {
    if data.len() != SECRET_STORAGE_SIZE {
        return None;
    }

    let ciphertext = data
        .get(..SECRET_STORAGE_SIZE - NONCE_SIZE)
        .unwrap()
        .to_vec();

    let nonce: [u8; NONCE_SIZE] = data
        .get(SECRET_STORAGE_SIZE - NONCE_SIZE..)
        .unwrap()
        .try_into()
        .expect("slice with incorrect length");

    Some((ciphertext, nonce))
}

#[cfg(test)]
mod test {
    use oasis_core_runtime::{
        common::{
            crypto::mrae::{
                deoxysii::{DeoxysII, KEY_SIZE},
                nonce::{Nonce, NONCE_SIZE},
            },
            namespace::{Namespace, NAMESPACE_SIZE},
        },
        consensus::beacon::EpochTime,
    };

    use crate::crypto::{self, Secret, SECRET_SIZE};

    #[test]
    fn basic_operations() {
        let runtime_id = Namespace([1; NAMESPACE_SIZE]);
        let epoch: EpochTime = 2;
        let generation: u64 = 3;
        let nonce = [4; NONCE_SIZE];
        let secret = Secret([5; SECRET_SIZE]);
        let key = [6; KEY_SIZE];

        let d2 = DeoxysII::new(&key);
        let encrypted_secret = d2.seal(&nonce, secret, vec![]);

        let data = crypto::pack_runtime_id_epoch(&runtime_id, epoch);
        let res = crypto::unpack_runtime_id_epoch(data).expect("data should unpack");
        assert_eq!((runtime_id, epoch), res);

        let res = crypto::unpack_runtime_id_epoch(vec![1, 2, 3]);
        assert_eq!(None, res);

        let data = crypto::pack_runtime_id_generation(&runtime_id, generation);
        let res = crypto::unpack_runtime_id_generation(data).expect("data should unpack");
        assert_eq!((runtime_id, generation), res);

        let res = crypto::unpack_runtime_id_generation(vec![1, 2, 3]);
        assert_eq!(None, res);

        let data = crypto::pack_runtime_id_generation_epoch(&runtime_id, generation, epoch);
        let res = crypto::unpack_runtime_id_generation_epoch(data).expect("data should unpack");
        assert_eq!((runtime_id, generation, epoch), res);

        let res = crypto::unpack_runtime_id_generation_epoch(vec![1, 2, 3]);
        assert_eq!(None, res);

        let data = crypto::pack_ciphertext_nonce(&encrypted_secret, &Nonce::new(nonce));
        let res = crypto::unpack_encrypted_secret_nonce(&data).expect("data should unpack");
        assert_eq!((encrypted_secret, nonce), res);

        let res = crypto::unpack_encrypted_secret_nonce(&vec![1, 2, 3]);
        assert_eq!(None, res);
    }
}
