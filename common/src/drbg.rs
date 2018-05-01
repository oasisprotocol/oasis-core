//! Deterministic Random Bit Generator.
use std::io::Cursor;

use byteorder::{LittleEndian, ReadBytesExt};

#[cfg(not(target_env = "sgx"))]
use rand::Rng;
#[cfg(target_env = "sgx")]
use sgx_rand::Rng;

use super::error::{Error, Result};
use super::ring::{digest, hmac};

/// The maximum length of the input entropy, personalization string, and
/// additional input, in bytes.
pub const MAX_LENGTH: u64 = 1 << 32; // 2^35 bits (u64 to handle 32 bit systems).
/// The minimum input entropy length, in bytes.
pub const MIN_LENGTH: usize = 256 / 8; // 256 bits.
/// The maximum output request size, in bytes.
pub const MAX_BYTES_PER_REQUEST: usize = 1 << 16; // 2^19 bits.
/// The re-seed interval, in number of requests.
const RESEED_INTERVAL: u64 = 1 << 48;

const OUT_LEN: usize = 512 / 8;
const RNG_BUFFER_SIZE: usize = OUT_LEN / 4; // 32 bit integers.

/// HMAC_DRBG instance (See: NIST SP 800-90A R1), using SHA-512.
///
/// WARNING: This implementation is primarily intended for deterministic
/// randomness generation from a public seed.  It does not provide prediction
/// resistance, and furthermore requires (as opposed to forbids) the consumer
/// to provide `entropy_input`.
///
/// DO NOT USE THIS TO GENERATE CRYPTOGRAPHIC KEY MATERIAL.
pub struct HmacDrbg {
    key: Vec<u8>,
    value: Vec<u8>,
    reseed_counter: u64,
}

impl HmacDrbg {
    /// Create a new HMAC_DRBG with the provided personalization string and
    /// initial entropy.
    ///
    /// The entropy_input must be [MIN_LENGTH, MAX_LENGTH] bytes long.
    /// The personalization_string must be [0, MAX_LENGTH] bytes long.
    pub fn new(entropy_input: &[u8], personalization_string: &[u8]) -> Result<Self> {
        // Sanity check the lengths of the inputs.
        if entropy_input.len() < MIN_LENGTH {
            return Err(Error::new("Insufficient entropy_input"));
        }
        if entropy_input.len() as u64 > MAX_LENGTH {
            return Err(Error::new("Excessive entropy_input"));
        }
        if personalization_string.len() as u64 > MAX_LENGTH {
            return Err(Error::new("Excessive personalization_string"));
        }

        // 10.1.2.3 Instantiation of HMAC_DRBG

        // 1. seed_material = entropy_input || nonce || personalization_string.
        let mut seed = Vec::with_capacity(entropy_input.len() + personalization_string.len());
        seed.extend_from_slice(entropy_input);
        seed.extend_from_slice(personalization_string);

        // 2. Key = 0x00 00...00. Comment: outlen bits.
        let k = vec![0; OUT_LEN];

        // 3. V = 0x01 01...01. Comment: outlen bits.
        let v = vec![1; OUT_LEN];

        let mut drbg = HmacDrbg {
            key: k,
            value: v,
            reseed_counter: 1, // 5. reseed_counter = 1.
        };

        // 4. (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
        drbg.update(Some(&seed));

        // 6. Return (V, Key. reseed_counter).
        Ok(drbg)
    }

    /// Generate pseudorandom bytes via the HMAC_DRBG.
    ///
    /// Each request must be for [0, MAX_BYTES_PER_REQUEST] bytes.
    /// The additional_input must be [0, MAX_LENGTH] bytes long.
    ///
    /// Each HmacDrbg instance may only service RESEED_INTERVAL requests.
    pub fn generate(
        &mut self,
        requested_number_of_bytes: usize,
        additional_input: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if requested_number_of_bytes > MAX_BYTES_PER_REQUEST {
            return Err(Error::new("Excessive request size"));
        }

        // 10.1.2.5 Generating Pseudorandom Bits Using HMAC_DRBG

        // 1. If reseed_counter > reseed_interval, then return an indication
        // that a reseed is required.
        if self.reseed_counter > RESEED_INTERVAL {
            // nb: Reseeding is not supported, and never will be, as it
            // propagates part of the internal state forward.
            return Err(Error::new("Reseeed required"));
        }

        // 2. If additional_input != Null, then (Key, V) = HMAC_DRBG_Update
        // (additional_input, Key, V).
        match additional_input {
            Some(a) => {
                if a.len() as u64 > MAX_LENGTH {
                    return Err(Error::new("Excessive additional input"));
                }
                self.update(additional_input);
            }
            None => {}
        }

        // 3. temp = Null.
        let temp_capacity = ((requested_number_of_bytes + OUT_LEN - 1) / OUT_LEN) * OUT_LEN;
        let mut temp = Vec::with_capacity(temp_capacity);

        // 4. While (len (temp) < requested_number_of_bits) do:
        let s_key = hmac::SigningKey::new(&digest::SHA512, &self.key);
        while temp.len() < requested_number_of_bytes {
            // 4.1 V = HMAC (Key , V).
            let v = hmac::sign(&s_key, &self.value);
            self.value[..].copy_from_slice(v.as_ref());

            // 4.2 temp = temp || V.
            temp.extend_from_slice(&self.value);
        }

        // 5. returned_bits = leftmost (temp, requested_number_of_bits).
        temp.truncate(requested_number_of_bytes);
        let returned_bytes = temp;

        // 6. (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
        self.update(additional_input);

        // 7. reseed_counter = reseed_counter + 1.
        self.reseed_counter = self.reseed_counter + 1;

        // 8. Return (SUCCESS, returned_bits, Key, V, reseed_counter).
        Ok(returned_bytes)
    }

    fn update(&mut self, provided_data: Option<&[u8]>) {
        let plen: usize = match provided_data {
            Some(p) => p.len(),
            None => 0,
        };

        // 10.1.2.2 The HMAC_DRBG Update Function (Update)

        // 1. K = HMAC (K, V || 0x00 || provided_data).
        let mut v_base = Vec::with_capacity(self.value.len() + 1 + plen);
        v_base.extend_from_slice(&self.value);
        v_base.push(0x00);
        match provided_data {
            Some(p) => v_base.extend_from_slice(p),
            None => {}
        }
        let s_key = hmac::SigningKey::new(&digest::SHA512, &self.key);
        let k = hmac::sign(&s_key, &v_base);
        self.key[..].copy_from_slice(k.as_ref());

        // 2. V = HMAC (K, V).
        let s_key = hmac::SigningKey::new(&digest::SHA512, &self.key);
        let v = hmac::sign(&s_key, &self.value);
        self.value[..].copy_from_slice(v.as_ref());

        // 3. If (provided_data = Null), then return K and V.
        if provided_data.is_none() {
            return;
        }

        // 4. K = HMAC (K, V || 0x01 || provided_data).
        v_base[..self.value.len()].copy_from_slice(&self.value);
        v_base[self.value.len()] = 0x01;
        let s_key = hmac::SigningKey::new(&digest::SHA512, &self.key);
        let k = hmac::sign(&s_key, &v_base);
        self.key[..].copy_from_slice(k.as_ref());

        // 5. V = HMAC (K, V).
        let s_key = hmac::SigningKey::new(&digest::SHA512, &self.key);
        let v = hmac::sign(&s_key, &self.value);
        self.value[..].copy_from_slice(v.as_ref());

        // 6. Return (K, V).
    }
}

/// HMAC_DRBG backed rand::Rng implementation.
///
/// DO NOT USE THIS TO GENERATE CRYPTOGRAPHIC KEY MATERIAL.
pub struct HmacDrbgRng {
    drbg: HmacDrbg,
    buffer: Vec<u32>,
    offset: usize,
}

impl HmacDrbgRng {
    /// Create a new HMAC_DRBG backed rand::Rng instance.
    ///
    /// The entropy_input must be [MIN_LENGTH, MAX_LENGTH] bytes long.
    /// The personalization_string must be [0, MAX_LENGTH] bytes long.
    pub fn new(entropy_input: &[u8], personalization_string: &[u8]) -> Result<Self> {
        let drbg = HmacDrbg::new(entropy_input, personalization_string)?;

        Ok(HmacDrbgRng {
            drbg: drbg,
            buffer: vec![0; RNG_BUFFER_SIZE],
            offset: RNG_BUFFER_SIZE,
        })
    }
}

impl Rng for HmacDrbgRng {
    fn next_u32(&mut self) -> u32 {
        if self.offset == RNG_BUFFER_SIZE {
            // Refill the buffer.
            //
            // Note: In practical terms this will *never* fail due to needing
            // a reseed, as each of the 2^48 allowed requests generates 16
            // u32s.
            let buf = self.drbg.generate(OUT_LEN, None).unwrap();
            let mut rdr = Cursor::new(buf);
            for i in &mut self.buffer {
                *i = rdr.read_u32::<LittleEndian>().unwrap();
            }
            self.offset = 0;
        }

        let returned_u32 = self.buffer[self.offset];
        self.buffer[self.offset] = 0; // Purge from buffer.
        self.offset = self.offset + 1;

        returned_u32
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_hex;
    extern crate serde_json;

    use self::rustc_hex::{FromHex, ToHex};
    use self::serde_json::Value;
    use super::*;

    // Compare against example output from NIST.
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_DRBG.pdf
    // Page 313 ->
    #[test]
    fn test_hmac_drbg_nist_example1() {
        let entropy_input = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E".from_hex().unwrap();
        let nonce = "202122232425262728292A2B2C2D2E2F".from_hex().unwrap();

        // HMAC_DRBG_Instantiate_algorithm
        let mut drbg = HmacDrbg::new(&entropy_input, &nonce).unwrap();
        assert_eq!(
            (*drbg.key).to_hex().to_ascii_uppercase(),
            "A7E118A531DEF956DCFF94BB3D801F775DC68F91696A434CC25E270E639044E1A7240266D3AA202D46C1054B610247535007DF12CFC8DA45982A587FC81C47D5",
        );
        assert_eq!(
            (*drbg.value).to_hex().to_ascii_uppercase(),
            "110793EAA60DC9DBCD4208104088A23DAECC1226EAF1D03BBA9D83A69599916571907346B15A0439362B9C8EE330E52DEACC639B98E8030A95780CD7C24B04D5",
        );

        // HMAC_DRBG_Generate
        let rnd_val = drbg.generate(1024 / 8, None).unwrap();
        assert_eq!(
            (*rnd_val).to_hex().to_ascii_uppercase(),
            "A463395AA79F237A22E5BD24462BD303E1BE5103BA37299BED170E10713EE9CDA62FABD5171231E1F6D82629BC521D41178D002D92918F397824E449004E9AE1851F7BFA11CD616EF519A9E2A05951D9108AB38959CA7E9E80B18ADFCC622389495795CBFB7D39AF6C8571DDCE035CA6890C7A1AF80861F0629EF1B6952BA206",
        );

        let rnd_val = drbg.generate(1024 / 8, None).unwrap();
        assert_eq!(
            (*rnd_val).to_hex().to_ascii_uppercase(),
            "FB5BD98D2CB25EC4955CD15204D68C497281CA0CE2201DACA5E412DDFDEBAF98D724D21662E45ABA9AE200D941C4CF76039808F29A8000346A6CC97D44417737A89F90472AC6088B45C666C561686F191745228F11ED556A519DA9AA1646D15B901382D87726D17DC5139FDEE1E8BDB0F328D4B105865BD1D815641E6B1DBA23",
        );
    }

    // Compare against NIST CAVP test vectors.
    //
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip
    // drbgvectors_no_reseed.zip (CAVS 14.3 - Tue Apr 02 15:42:24 2013)
    #[test]
    fn test_hmac_drbg_nist_cavp() {
        // The JSON file contains the test cases with the following parameters,
        // under the rationale that the nonce/personalization string are
        // functionally equivalent (See: 10.1.2.3), and this case exercises
        // everything else.
        //
        // [SHA-512]
        // [PredictionResistance = False]
        // [EntropyInputLen = 256]
        // [NonceLen = 128]
        // [PersonalizationStringLen = 0]
        // [AdditionalInputLen = 256]
        // [ReturnedBitsLen = 2048]
        //
        // nb: For the sake of brevity, only the final V/Key internal values
        // are included in the JSON.
        const RETURNED_BITS_LEN: usize = 2048 / 8; // in bytes
        let test_vectors = include_str!("../testdata/hmac_drbg.json");
        let test_vectors: Vec<Value> = serde_json::from_str(test_vectors).unwrap();

        let iter = test_vectors.iter();
        for test_vector in iter {
            // Per the Readme.txt, the ReturnedBits is the value returned from
            // the second call to Generate.

            // It's this or pulling in serde_derive, I went with this.
            let entropy_input = test_vector["EntropyInput"]
                .as_str()
                .unwrap()
                .from_hex()
                .unwrap();
            let nonce = test_vector["Nonce"].as_str().unwrap().from_hex().unwrap();
            let additional_input = test_vector["AdditionalInput"]
                .as_str()
                .unwrap()
                .from_hex()
                .unwrap();
            let additional_input_2 = test_vector["AdditionalInput_2"]
                .as_str()
                .unwrap()
                .from_hex()
                .unwrap();
            let returned_bits = test_vector["ReturnedBits"]
                .as_str()
                .unwrap()
                .from_hex()
                .unwrap();
            let v = test_vector["V"].as_str().unwrap().from_hex().unwrap();
            let key = test_vector["Key"].as_str().unwrap().from_hex().unwrap();

            let mut drbg = HmacDrbg::new(&entropy_input, &nonce).unwrap();
            let _ = drbg.generate(RETURNED_BITS_LEN, Some(&additional_input))
                .unwrap();
            let rnd_val = drbg.generate(RETURNED_BITS_LEN, Some(&additional_input_2))
                .unwrap();

            assert_eq!(rnd_val, returned_bits);
            assert_eq!(drbg.value, v);
            assert_eq!(drbg.key, key);
        }
    }

    // Test the rand::Rng interface.
    #[test]
    fn test_hmac_drbg_rng() {
        let entropy_input = "Reaching out to embrace the random".as_bytes();
        let personalization_string = "Reaching out to embrace whatever may come".as_bytes();

        let mut rng = HmacDrbgRng::new(entropy_input, personalization_string).unwrap();
        let mut drbg = HmacDrbg::new(entropy_input, personalization_string).unwrap();

        // Sample at least 2 HmacDrbg::generate() calls worth of output.
        let mut buf = Vec::with_capacity(2 * OUT_LEN);
        buf.extend_from_slice(&drbg.generate(OUT_LEN, None).unwrap());
        buf.extend_from_slice(&drbg.generate(OUT_LEN, None).unwrap());
        let mut rdr = Cursor::new(buf);

        // Ensure the rand::Rng instance produces the same output as the
        // sample from the HmacDrbg (interpreted as little endian u32s).
        for _ in 0..RNG_BUFFER_SIZE * 2 {
            let expected = rdr.read_u32::<LittleEndian>().unwrap();
            assert_eq!(rng.next_u32(), expected);
        }

        // Check to see if the rand crate broke backwards compatibility.
        let mut rng = HmacDrbgRng::new(entropy_input, personalization_string).unwrap();
        let mut v = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let v_expected = [5, 9, 3, 0, 6, 8, 1, 2, 7, 4]; // rand = "0.4.2"
        rng.shuffle(&mut v);
        assert_eq!(v, v_expected);
    }
}
