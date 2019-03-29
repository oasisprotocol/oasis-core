//! Deoxys-II-256-128 MRAE primitives implementation.
use super::{
    core::arch::x86_64::{
        __m128i, _mm_aesenc_si128, _mm_and_si128, _mm_load_si128, _mm_loadu_si128, _mm_or_si128,
        _mm_set1_epi8, _mm_set_epi64x, _mm_set_epi8, _mm_shuffle_epi8, _mm_slli_epi64,
        _mm_srli_epi64, _mm_store_si128, _mm_storeu_si128, _mm_xor_si128,
    },
    error::{Error, Result},
    ring::{constant_time::verify_slices_are_equal, digest, hmac},
    sodalite::{scalarmult, scalarmult_base},
    zeroize::{Zeroize, ZeroizeOnDrop},
};

#[cfg(not(target_env = "sgx"))]
use rand::{OsRng as TheRng, Rng};
#[cfg(target_env = "sgx")]
use sgx_rand::{Rng, SgxRng as TheRng};

/// Size of the Deoxys-II-256-128 key in bytes.
pub const KEY_SIZE: usize = 32;
/// Size of the nonce in bytes.
pub const NONCE_SIZE: usize = 15;
/// Size of the authentication tag in bytes.
pub const TAG_SIZE: usize = 16;

/// Size of the block used in the block cipher in bytes.
const BLOCK_SIZE: usize = 16;
/// Number of rounds used in the block cipher.
const ROUNDS: usize = 16;
/// Size of the tweak in bytes.
const TWEAK_SIZE: usize = 16;
/// Size of the sub-tweak key in bytes.
const STK_SIZE: usize = 16;
/// Number of sub-tweak keys.
const STK_COUNT: usize = ROUNDS + 1;

/// Block prefixes.
const PREFIX_SHIFT: usize = 4;
const PREFIX_AD_BLOCK: u8 = 0b0010;
const PREFIX_AD_FINAL: u8 = 0b0110;
const PREFIX_MSG_BLOCK: u8 = 0b0000;
const PREFIX_MSG_FINAL: u8 = 0b0100;
const PREFIX_TAG: u8 = 0b0001;

/// Hack that enables us to have __m128i vector constants.
#[repr(C)]
union u8x16 {
    v: __m128i,
    b: [u8; 16],
}

/// Generates a `__m128i` vector from given `u8` components.
/// The order of components is lowest to highest.
///
/// Note that the order of components is the reverse of `_mm_set_epi8`,
/// which goes from highest component to lowest!
/// Also, we use `u8` components, while `_mm_set_epi8` uses `i8` components.
///
/// This macro exists only because it's not possible to use `_mm_set_epi8`
/// to produce constant vectors.
macro_rules! m128i_vec {
    ( $( $x:expr ),* ) => { unsafe { (u8x16 { b: [$($x,)*] } ).v } };
}

/// Byte shuffle order for the h() function, apply it with `_mm_shuffle_epi8`.
const H_SHUFFLE: __m128i = m128i_vec![7, 0, 13, 10, 11, 4, 1, 14, 15, 8, 5, 2, 3, 12, 9, 6];

/// This shuffle order converts the lower half of the vector from little-endian
/// to big-endian and moves it to the upper half, clearing the lower half to
/// zero (the 0x80 constants set the corresponding byte to zero).
const LE2BE_SHUFFLE: __m128i =
    m128i_vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 7, 6, 5, 4, 3, 2, 1, 0];

/// Deoxys-II-256-128 state.
///
/// We don't store the key itself, but only components derived from the key.
/// These components are automatically erased after the structure is dropped.
#[derive(ZeroizeOnDrop)]
#[repr(align(16))]
pub struct DeoxysII {
    /// Derived K components for the sub-tweak keys for each round.
    /// These are derived from the key.
    derived_ks: [[u8; STK_SIZE]; STK_COUNT],
}

impl Zeroize for DeoxysII {
    /// Make sure the derived K components are erased before the struct
    /// is dropped, as they contain sensitive information.
    fn zeroize(&mut self) {
        for i in 0..STK_COUNT {
            self.derived_ks[i].zeroize();
        }
    }
}

impl DeoxysII {
    /// Creates a new instance using the provided `key`.
    pub fn new(key: &[u8; KEY_SIZE]) -> Result<Self> {
        Ok(Self {
            derived_ks: stk_derive_k(key),
        })
    }

    /// Encrypts and authenticates plaintext, authenticates the additional
    /// data and returns the result.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let pt_len = plaintext.len();

        let mut tweak = [0u8; TWEAK_SIZE];
        let mut tmp = [0u8; BLOCK_SIZE];

        // Handle additional data.
        let mut ad_len = additional_data.len();
        let mut auth = [0u8; TAG_SIZE];
        let mut i: usize = 0;
        while ad_len >= BLOCK_SIZE {
            // auth <- auth ^ Ek(0010||i, Ai+1)
            encode_tag_tweak(&mut tweak, PREFIX_AD_BLOCK, i as u64);
            bc_encrypt(
                &mut tmp,
                &self.derived_ks,
                &tweak,
                &additional_data[i * BLOCK_SIZE..i * BLOCK_SIZE + BLOCK_SIZE],
            );
            xor_block_inplace(&mut auth, &tmp);

            ad_len -= BLOCK_SIZE;
            i += 1;
        }
        if ad_len > 0 {
            let remaining = ad_len;

            // auth <- auth ^ Ek(0110||la, pad10*(A*))
            encode_tag_tweak(&mut tweak, PREFIX_AD_FINAL, i as u64);

            let mut astar = [0u8; BLOCK_SIZE];
            astar[..remaining]
                .copy_from_slice(&additional_data[additional_data.len() - remaining..]);
            astar[remaining] = 0x80;

            bc_encrypt(&mut tmp, &self.derived_ks, &tweak, &astar);
            xor_block_inplace(&mut auth, &tmp);
        }

        // Handle message authentication and tag generation.
        let mut msg_len = pt_len;
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&auth);
        let mut j: usize = 0;
        while msg_len >= BLOCK_SIZE {
            // tag <- tag ^ Ek(0000||j, Mj+1)
            encode_tag_tweak(&mut tweak, PREFIX_MSG_BLOCK, j as u64);
            bc_encrypt(
                &mut tmp,
                &self.derived_ks,
                &tweak,
                &plaintext[j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE],
            );
            xor_block_inplace(&mut tag, &tmp);

            msg_len -= BLOCK_SIZE;
            j += 1;
        }
        if msg_len > 0 {
            let remaining = msg_len;

            // tag <- tag ^ Ek(0100||l, pad10*(M*))
            encode_tag_tweak(&mut tweak, PREFIX_MSG_FINAL, j as u64);

            let mut mstar = [0u8; BLOCK_SIZE];
            mstar[..remaining].copy_from_slice(&plaintext[pt_len - remaining..]);
            mstar[remaining] = 0x80;

            bc_encrypt(&mut tmp, &self.derived_ks, &tweak, &mstar);
            xor_block_inplace(&mut tag, &tmp);
        }

        // Handle nonce.
        // tag <- Ek(0001||0000||N, tag)
        let mut enc_nonce = [0u8; BLOCK_SIZE];
        enc_nonce[1..].copy_from_slice(nonce);
        enc_nonce[0] = PREFIX_TAG << PREFIX_SHIFT;
        let tc = tag.clone();
        bc_encrypt(&mut tag, &self.derived_ks, &enc_nonce, &tc);

        // Allocate storage for the ciphertext.
        let mut c = Vec::with_capacity(pt_len + TAG_SIZE);
        unsafe {
            c.set_len(pt_len + TAG_SIZE);
        }

        // Put the tag at the end.
        c[pt_len..pt_len + TAG_SIZE].copy_from_slice(&tag);

        // Encrypt message.
        let mut enc_blk = [0u8; BLOCK_SIZE];
        enc_nonce[0] = 0;

        // encode_enc_tweak() requires the first byte of the tag to be modified.
        tag[0] |= 0x80;

        msg_len = pt_len;
        j = 0;
        while msg_len >= BLOCK_SIZE {
            // Cj <- Mj ^ Ek(1||tag^j, 00000000||N)
            encode_enc_tweak(&mut tweak, &tag, j as u64);
            bc_encrypt(&mut enc_blk, &self.derived_ks, &tweak, &enc_nonce);
            let range = j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE;
            xor_block(&mut c[range.clone()], &plaintext[range], &enc_blk);

            msg_len -= BLOCK_SIZE;
            j += 1;
        }
        if msg_len > 0 {
            let remaining = msg_len;

            // C* <- M* ^ Ek(1||tag^1, 00000000||N)
            encode_enc_tweak(&mut tweak, &tag, j as u64);
            bc_encrypt(&mut enc_blk, &self.derived_ks, &tweak, &enc_nonce);
            let range = j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE;
            xor_bytes(
                &mut c[range],
                &plaintext[j * BLOCK_SIZE..],
                &enc_blk,
                remaining,
            );
        }

        Ok(c)
    }

    /// Decrypts and authenticates ciphertext, authenticates the additional
    /// data and, if successful, returns the resulting plaintext.
    /// If the tag verification fails, an error is returned and the
    /// intermediary plaintext is securely erased from memory.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext_with_tag: Vec<u8>,
        additional_data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if ciphertext_with_tag.len() < TAG_SIZE {
            return Err(Error::new("deoxysii: ciphertext too short"));
        }

        let mut ct_len = ciphertext_with_tag.len() - TAG_SIZE;
        let ciphertext = &ciphertext_with_tag[0..ct_len];
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&ciphertext_with_tag[ct_len..]);

        // Decrypt message.
        let mut plaintext = Vec::with_capacity(ct_len);
        unsafe {
            plaintext.set_len(ct_len);
        }
        let mut dec_tweak = [0u8; TWEAK_SIZE];
        let mut dec_blk = [0u8; BLOCK_SIZE];
        let mut dec_nonce = [0u8; BLOCK_SIZE];
        let mut j: usize = 0;

        // 0x00 || nonce
        dec_nonce[1..].copy_from_slice(nonce);

        // encode_enc_tweak() requires the first byte of the tag to be modified.
        let prev_tag0 = tag[0];
        tag[0] |= 0x80;

        while ct_len >= BLOCK_SIZE {
            // Mj <- Cj ^ Ek(1||tag^j, 00000000||N)
            encode_enc_tweak(&mut dec_tweak, &tag, j as u64);
            bc_encrypt(&mut dec_blk, &self.derived_ks, &dec_tweak, &dec_nonce);
            let range = j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE;
            xor_block(&mut plaintext[range.clone()], &ciphertext[range], &dec_blk);

            ct_len -= BLOCK_SIZE;
            j += 1;
        }
        if ct_len > 0 {
            // M* <- C* ^ Ek(1||tag^1, 00000000||N)
            encode_enc_tweak(&mut dec_tweak, &tag, j as u64);
            bc_encrypt(&mut dec_blk, &self.derived_ks, &dec_tweak, &dec_nonce);
            xor_bytes(
                &mut plaintext[j * BLOCK_SIZE..],
                &ciphertext[j * BLOCK_SIZE..],
                &dec_blk,
                ct_len,
            );
        }

        // Undo the tag modification required for encode_enc_tweak().
        tag[0] = prev_tag0;

        // Handle associated data.
        let mut ad_len = additional_data.len();
        let mut auth = [0u8; TAG_SIZE];
        let mut tweak = [0u8; TWEAK_SIZE];
        let mut tmp = [0u8; BLOCK_SIZE];
        let mut i: usize = 0;

        while ad_len >= BLOCK_SIZE {
            // auth <- auth ^ Ek(0010||i, Ai+1)
            encode_tag_tweak(&mut tweak, PREFIX_AD_BLOCK, i as u64);
            bc_encrypt(
                &mut tmp,
                &self.derived_ks,
                &tweak,
                &additional_data[i * BLOCK_SIZE..i * BLOCK_SIZE + BLOCK_SIZE],
            );
            xor_block_inplace(&mut auth, &tmp);

            ad_len -= BLOCK_SIZE;
            i += 1;
        }
        if ad_len > 0 {
            let remaining = ad_len;

            // auth <- auth ^ Ek(0110||la, pad10*(A*))
            encode_tag_tweak(&mut tweak, PREFIX_AD_FINAL, i as u64);

            let mut astar = [0u8; BLOCK_SIZE];
            astar[..remaining]
                .copy_from_slice(&additional_data[additional_data.len() - remaining..]);
            astar[ad_len] = 0x80;

            bc_encrypt(&mut tmp, &self.derived_ks, &tweak, &astar);
            xor_block_inplace(&mut auth, &tmp);
        }

        // Handle message authentication and tag generation.
        let mut msg_len = plaintext.len();
        let mut tag_p = [0u8; TAG_SIZE];
        tag_p.copy_from_slice(&auth);
        j = 0;

        while msg_len >= BLOCK_SIZE {
            // tag' <- tag' ^ Ek(0000||j, Mj+1)
            encode_tag_tweak(&mut tweak, PREFIX_MSG_BLOCK, j as u64);
            bc_encrypt(
                &mut tmp,
                &self.derived_ks,
                &tweak,
                &plaintext[j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE],
            );
            xor_block_inplace(&mut tag_p, &tmp);

            msg_len -= BLOCK_SIZE;
            j += 1;
        }
        if msg_len > 0 {
            let remaining = msg_len;

            // tag <- tag ^ Ek(0100||l, pad10*(M*))
            encode_tag_tweak(&mut tweak, PREFIX_MSG_FINAL, j as u64);

            let mut mstar = [0u8; BLOCK_SIZE];
            mstar[..remaining].copy_from_slice(&plaintext[plaintext.len() - remaining..]);
            mstar[msg_len] = 0x80;

            bc_encrypt(&mut tmp, &self.derived_ks, &tweak, &mstar);
            xor_block_inplace(&mut tag_p, &tmp);
        }

        // tag' <- Ek(0001||0000||N, tag')
        dec_nonce[0] = PREFIX_TAG << PREFIX_SHIFT;
        let tpc = tag_p.clone();
        bc_encrypt(&mut tag_p, &self.derived_ks, &dec_nonce, &tpc);

        // Verify tag.
        if !verify_slices_are_equal(&tag, &tag_p).is_ok() {
            plaintext.zeroize();
            tag.zeroize();
            tag_p.zeroize();
            Err(Error::new("deoxysii: tag verification failed"))
        } else {
            Ok(plaintext)
        }
    }
}

/// Performs `out <- a XOR b` for every byte.
#[inline]
fn xor_bytes(out: &mut [u8], a: &[u8], b: &[u8], n: usize) {
    // Use `xor_block()` or `xor_block_inplace()` for BLOCK_SIZEd xors.
    debug_assert!(n < BLOCK_SIZE);

    for i in 0..n {
        out[i] = a[i] ^ b[i];
    }
}

/// Same as `xor_bytes`, but `n == BLOCK_SIZE`.
#[inline]
fn xor_block(out: &mut [u8], a: &[u8], b: &[u8]) {
    unsafe {
        let xa = _mm_loadu_si128(a.as_ptr() as *const __m128i);
        let xb = _mm_loadu_si128(b.as_ptr() as *const __m128i);

        let xout = _mm_xor_si128(xa, xb);

        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, xout);
    }
}

/// Same as `xor_block`, but `out == a`.
#[inline]
fn xor_block_inplace(out: &mut [u8], b: &[u8]) {
    unsafe {
        let xo = _mm_loadu_si128(out.as_ptr() as *const __m128i);
        let xb = _mm_loadu_si128(b.as_ptr() as *const __m128i);

        let xout = _mm_xor_si128(xo, xb);

        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, xout);
    }
}

/// Macro to generate the constant vectors for conditioning the sub-tweak
/// keys for each round.
macro_rules! generate_rcon_matrix {
    ( $( $x:expr ),* ) => {
        [$(m128i_vec![1, 2, 4, 8, $x, $x, $x, $x, 0, 0, 0, 0, 0, 0, 0, 0],)*]
    };
}

/// Vectors from the generated RCON matrix are used when deriving partial
/// sub-tweak keys from the actual key (see `stk_derive_k()`).
const RCON: [__m128i; STK_COUNT] = generate_rcon_matrix![
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72
];

/// Derives the K component of the sub-tweak key (STK) for each round.
/// The derived partial STK is passed to seal/open instead of the actual
/// key.
fn stk_derive_k(key: &[u8; KEY_SIZE]) -> [[u8; STK_SIZE]; STK_COUNT] {
    debug_assert!(STK_SIZE == BLOCK_SIZE);
    debug_assert!(STK_SIZE == 16);

    unsafe {
        #[repr(align(16))]
        struct DKS([[u8; STK_SIZE]; STK_COUNT]);
        let mut derived_ks = DKS([[0u8; STK_SIZE]; STK_COUNT]);

        // LFSR masks for the vector bitops.
        let lfsr_x0_mask = _mm_set1_epi8(1);
        let lfsr_invx0_mask = _mm_set1_epi8(-2); // 0xfe
        let lfsr_x7_mask = _mm_set1_epi8(-128); // 0x80
        let lfsr_invx7_mask = _mm_set1_epi8(127); // 0x7f

        let mut tk2 = _mm_loadu_si128(key[16..32].as_ptr() as *const __m128i);
        let mut tk3 = _mm_loadu_si128(key[0..16].as_ptr() as *const __m128i);

        // First iteration.
        let mut dk0 = _mm_xor_si128(tk2, tk3);
        dk0 = _mm_xor_si128(dk0, RCON[0]);
        _mm_store_si128(derived_ks.0[0].as_mut_ptr() as *mut __m128i, dk0);

        // Remaining iterations.
        for i in 1..ROUNDS + 1 {
            // Tk2(i+1) = h(LFSR2(Tk2(i)))
            let x1sr7 = _mm_srli_epi64(tk2, 7);
            let x1sr5 = _mm_srli_epi64(tk2, 5);
            tk2 = _mm_slli_epi64(tk2, 1);
            tk2 = _mm_and_si128(tk2, lfsr_invx0_mask);
            let x7xorx5 = _mm_xor_si128(x1sr7, x1sr5);
            let x7xorx5_and_1 = _mm_and_si128(x7xorx5, lfsr_x0_mask);
            tk2 = _mm_or_si128(tk2, x7xorx5_and_1);

            tk2 = _mm_shuffle_epi8(tk2, H_SHUFFLE);

            // Tk3(i+1) = h(LFSR3(Tk3(i)))
            let x2sl7 = _mm_slli_epi64(tk3, 7);
            let x2sl1 = _mm_slli_epi64(tk3, 1);
            tk3 = _mm_srli_epi64(tk3, 1);
            tk3 = _mm_and_si128(tk3, lfsr_invx7_mask);
            let x7xorx1 = _mm_xor_si128(x2sl7, x2sl1);
            let x7xorx1_and_1 = _mm_and_si128(x7xorx1, lfsr_x7_mask);
            tk3 = _mm_or_si128(tk3, x7xorx1_and_1);

            tk3 = _mm_shuffle_epi8(tk3, H_SHUFFLE);

            let mut dki = _mm_xor_si128(tk2, tk3);
            dki = _mm_xor_si128(dki, RCON[i]);

            _mm_store_si128(derived_ks.0[i].as_mut_ptr() as *mut __m128i, dki);
        }

        derived_ks.0
    }
}

/// Performs block encryption using the block cypher.
fn bc_encrypt(
    ciphertext: &mut [u8; BLOCK_SIZE],
    derived_ks: &[[u8; STK_SIZE]; STK_COUNT],
    tweak: &[u8; TWEAK_SIZE],
    plaintext: &[u8],
) {
    debug_assert!(plaintext.len() == BLOCK_SIZE);
    debug_assert!(BLOCK_SIZE == 16);

    unsafe {
        // First iteration: load plaintext, derive first sub-tweak key, then
        // xor it with the plaintext.
        let pt = _mm_loadu_si128(plaintext.as_ptr() as *const __m128i);
        let dk0 = _mm_load_si128(derived_ks[0].as_ptr() as *const __m128i);
        let mut tk1 = _mm_loadu_si128(tweak.as_ptr() as *const __m128i);
        let stk1 = _mm_xor_si128(dk0, tk1);
        let mut ct = _mm_xor_si128(pt, stk1);

        // Remaining iterations.
        for i in 1..ROUNDS + 1 {
            // Derive sub-tweak key for this round.
            let dki = _mm_load_si128(derived_ks[i].as_ptr() as *const __m128i);
            tk1 = _mm_shuffle_epi8(tk1, H_SHUFFLE);
            let round_key = _mm_xor_si128(dki, tk1);

            // Perform AESENC on the block.
            ct = _mm_aesenc_si128(ct, round_key);
        }

        _mm_storeu_si128(ciphertext.as_mut_ptr() as *mut __m128i, ct);
    }
}

#[inline]
fn encode_tag_tweak(out: &mut [u8; TWEAK_SIZE], prefix: u8, block_num: u64) {
    unsafe {
        // Load block number into lower half of vector.
        let bnum = _mm_set_epi64x(0, block_num as i64);

        // Convert it to big-endian and shift to upper half.
        let bnum_be = _mm_shuffle_epi8(bnum, LE2BE_SHUFFLE);

        // First byte of output is the shifted prefix.
        let p = (prefix << PREFIX_SHIFT) as i8;
        let xp = _mm_set_epi8(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, p);
        let xo = _mm_or_si128(bnum_be, xp);

        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, xo);
    }
}

#[inline]
fn encode_enc_tweak(out: &mut [u8; TWEAK_SIZE], tag: &[u8; TAG_SIZE], block_num: u64) {
    unsafe {
        // Convert block number to big-endian and move it to the upper half
        // of the vector, clearing the lower half to zero.
        let bnum = _mm_set_epi64x(0, block_num as i64);
        let bnum_be = _mm_shuffle_epi8(bnum, LE2BE_SHUFFLE);

        // Load tag that was previously ORed with 0x80 in the caller.
        let ored_tag = _mm_loadu_si128(tag.as_ptr() as *const __m128i);

        // XOR tag with the block number.
        let ored_tag_xor_bn = _mm_xor_si128(ored_tag, bnum_be);

        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, ored_tag_xor_bn);
    }
}

/// Derives a MRAE AEAD symmetric key suitable for use with the asymmetric
/// box primitives from the provided X25519 public and private keys.
pub fn derive_symmetric_key(public: &[u8; 32], private: &[u8; 32]) -> [u8; KEY_SIZE] {
    let mut pmk = [0u8; 32];
    scalarmult(&mut pmk, private, public);

    let k = hmac::SigningKey::new(&digest::SHA384, b"MRAE_Box_Deoxys-II-256-128");
    let mut ctx = hmac::SigningContext::with_key(&k);

    ctx.update(&pmk);
    pmk.zeroize();

    let mut derived_key = [0u8; KEY_SIZE];
    derived_key.copy_from_slice(&ctx.sign().as_ref()[..KEY_SIZE]);

    derived_key
}

/// Generates a public/private key pair suitable for use with
/// `derive_symmetric_key`, `box_seal`, and `box_open`.
pub fn generate_key_pair() -> ([u8; 32], [u8; 32]) {
    let mut rng = TheRng::new().unwrap();

    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&digest::digest(&digest::SHA512_256, &entropy).as_ref()[..32]);
    entropy.zeroize();

    let mut public_key = [0u8; 32];
    scalarmult_base(&mut public_key, &private_key);

    (public_key, private_key)
}

/// Boxes ("seals") the provided additional data and plaintext via
/// Deoxys-II-256-128 using a symmetric key derived from the provided
/// X25519 public and private keys.
/// The nonce should be `NONCE_SIZE` bytes long and unique for all time
/// for a given public and private key tuple.
pub fn box_seal(
    nonce: &[u8; NONCE_SIZE],
    plaintext: Vec<u8>,
    additional_data: Vec<u8>,
    peers_public_key: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let key = derive_symmetric_key(peers_public_key, private_key);

    let d2 = DeoxysII::new(&key)?;

    d2.seal(nonce, plaintext, additional_data)
}

/// Unboxes ("opens") the provided additional data and ciphertext via
/// Deoxys-II-256-128 using a symmetric key derived from the provided
/// X25519 public and private keys.
/// The nonce should be `NONCE_SIZE` bytes long and both it and the additional
/// data must match the value passed to `box_seal`.
pub fn box_open(
    nonce: &[u8; NONCE_SIZE],
    ciphertext: Vec<u8>,
    additional_data: Vec<u8>,
    peers_public_key: &[u8; 32],
    private_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let key = derive_symmetric_key(peers_public_key, private_key);

    let d2 = DeoxysII::new(&key)?;

    d2.open(nonce, ciphertext, additional_data)
}

// RUST_BACKTRACE=full RUSTFLAGS="-C target-feature=+aes,+sse2,+sse3,+ssse3,+avx,+avx2" cargo test -- mrae::deoxysii::tests::test

// RUSTFLAGS="-C target-feature=+aes,+sse2,+sse3,+ssse3,+avx,+avx2" cargo bench -- mrae::deoxysii::tests::bench

#[cfg(test)]
mod tests {
    extern crate base64;
    extern crate serde_json;
    extern crate test;

    use self::{
        base64::decode,
        serde_json::{Map, Value},
        test::{black_box, Bencher},
    };
    use super::*;

    #[test]
    fn test_mrae_basic() {
        let key = [0u8; KEY_SIZE];
        let d2 = DeoxysII::new(&key);
        assert!(d2.is_ok());
        let d2 = d2.unwrap();

        // Should successfully seal the text.
        let nonce = [1u8; NONCE_SIZE];
        let text = String::from("This is a test!").as_bytes().to_vec();
        let aad = vec![42; 10];
        let sealed = d2.seal(&nonce, text.clone(), aad.clone());
        assert!(sealed.is_ok());
        let ciphertext = sealed.unwrap();

        // Should successfully open the text and the text should match.
        let opened = d2.open(&nonce, ciphertext.clone(), aad.clone());
        assert!(opened.is_ok());
        assert!(opened.unwrap() == text);

        // Should fail if the nonce is different.
        let fake_nonce = [2u8; NONCE_SIZE];
        let fail_opened = d2.open(&fake_nonce, ciphertext.clone(), aad.clone());
        assert!(fail_opened.is_err());

        // Should fail if the additional data is different.
        let fake_aad = vec![47; 10];
        let fail_opened = d2.open(&nonce, ciphertext.clone(), fake_aad.clone());
        assert!(fail_opened.is_err());

        // Should fail if the both the nonce and the additional data are different.
        let fake_nonce = [3u8; NONCE_SIZE];
        let fake_aad = vec![4; 5];
        let fail_opened = d2.open(&fake_nonce, ciphertext.clone(), fake_aad.clone());
        assert!(fail_opened.is_err());

        // Should handle too short ciphertext.
        let fail_opened = d2.open(&nonce, vec![1, 2, 3], aad.clone());
        assert!(fail_opened.is_err());

        // Should fail on damaged ciphertext.
        let mut malformed_ciphertext = ciphertext.clone();
        malformed_ciphertext[3] ^= 0xa5;
        let fail_opened = d2.open(&nonce, malformed_ciphertext, aad.clone());
        assert!(fail_opened.is_err());

        // Should fail on truncated ciphertext.
        let mut truncated_ciphertext = ciphertext.clone();
        truncated_ciphertext.truncate(ciphertext.len() - 5);
        let fail_opened = d2.open(&nonce, truncated_ciphertext, aad.clone());
        assert!(fail_opened.is_err());
    }

    #[test]
    fn test_mrae_nonblocksized() {
        let key = [42u8; KEY_SIZE];
        let d2 = DeoxysII::new(&key);
        assert!(d2.is_ok());
        let d2 = d2.unwrap();

        // Should successfully seal msg with non-block-sized additional data.
        let nonce = [7u8; NONCE_SIZE];
        let mut text = Vec::with_capacity(BLOCK_SIZE * 7 + 3);
        for i in 0..text.capacity() {
            text.push(i as u8);
        }
        let mut aad = Vec::with_capacity(BLOCK_SIZE + 5);
        for i in 0..aad.capacity() {
            aad.push(i as u8);
        }
        let sealed = d2.seal(&nonce, text.clone(), aad.clone());
        assert!(sealed.is_ok());
        let ciphertext = sealed.unwrap();

        // Should successfully open the text and the text should match.
        let opened = d2.open(&nonce, ciphertext.clone(), aad.clone());
        assert!(opened.is_ok());
        assert!(opened.unwrap() == text);
    }

    #[test]
    fn test_mrae_blocksized() {
        let key = [42u8; KEY_SIZE];
        let d2 = DeoxysII::new(&key);
        assert!(d2.is_ok());
        let d2 = d2.unwrap();

        // Should successfully seal msg with block-sized additional data.
        let nonce = [7u8; NONCE_SIZE];
        let mut text = Vec::with_capacity(BLOCK_SIZE * 8);
        for i in 0..text.capacity() {
            text.push(i as u8);
        }
        let mut aad = Vec::with_capacity(BLOCK_SIZE);
        for i in 0..aad.capacity() {
            aad.push(i as u8);
        }
        let sealed = d2.seal(&nonce, text.clone(), aad.clone());
        assert!(sealed.is_ok());
        let ciphertext = sealed.unwrap();

        // Should successfully open the text and the text should match.
        let opened = d2.open(&nonce, ciphertext.clone(), aad.clone());
        assert!(opened.is_ok());
        assert!(opened.unwrap() == text);
    }

    #[test]
    fn test_mrae_vectors() {
        let test_vectors = include_str!("./testdata/Deoxys-II-256-128.json");
        let test_vectors: Map<String, Value> = serde_json::from_str(test_vectors).unwrap();

        let key_vec = decode(test_vectors["Key"].as_str().unwrap())
            .unwrap()
            .to_vec();
        let msg = decode(test_vectors["MsgData"].as_str().unwrap())
            .unwrap()
            .to_vec();
        let aad = decode(test_vectors["AADData"].as_str().unwrap())
            .unwrap()
            .to_vec();
        let nonce_vec = decode(test_vectors["Nonce"].as_str().unwrap())
            .unwrap()
            .to_vec();

        let mut key = [0u8; KEY_SIZE];
        let mut nonce = [0u8; NONCE_SIZE];
        key.copy_from_slice(&key_vec);
        nonce.copy_from_slice(&nonce_vec);

        let d2 = DeoxysII::new(&key).unwrap();

        for v in test_vectors["KnownAnswers"].as_array().unwrap().iter() {
            let ciphertext = decode(v["Ciphertext"].as_str().unwrap()).unwrap().to_vec();
            let tag = decode(v["Tag"].as_str().unwrap()).unwrap().to_vec();
            let length: usize = v["Length"].as_u64().unwrap() as usize;

            let ct = d2
                .seal(&nonce, msg[..length].to_vec(), aad[..length].to_vec())
                .unwrap();

            assert_eq!(ct.len(), length + TAG_SIZE);

            let t = ct[length..].to_vec();
            let ct = ct[..length].to_vec();

            assert_eq!(ciphertext, ct);
            assert_eq!(tag, t);
        }
    }

    #[test]
    fn test_mrae_asymmetric() {
        let (a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, b_priv) = generate_key_pair(); // Bob

        // None of the generated keys should be the same.
        assert_ne!(a_pub, b_pub);
        assert_ne!(a_priv, b_priv);
        assert_ne!(a_pub, a_priv);
        assert_ne!(b_pub, b_priv);

        // Should successfully seal the text in a box.
        let nonce = [1u8; NONCE_SIZE];
        let text = String::from("This is a test!").as_bytes().to_vec();
        let aad = vec![42u8; 10];

        let sealed = box_seal(&nonce, text.clone(), aad.clone(), &b_pub, &a_priv);
        assert!(sealed.is_ok());

        // Should successfully open the sealed box.
        let opened = box_open(&nonce, sealed.unwrap(), aad, &a_pub, &b_priv);
        assert!(opened.is_ok());

        // The deciphered text should match the original.
        let deciphered = opened.unwrap();
        assert_eq!(deciphered, text);
    }

    #[bench]
    fn bench_mrae_seal_4096(b: &mut Bencher) {
        let mut rng = TheRng::new().unwrap();

        // Set up the key.
        let mut key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut key);
        let d2 = DeoxysII::new(&key).unwrap();

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill_bytes(&mut text);
        let mut aad = [0u8; 64];
        rng.fill_bytes(&mut aad);

        // Benchmark sealing.
        b.iter(|| {
            let text = text.to_vec();
            let aad = aad.to_vec();
            let _sealed = black_box(d2.seal(&nonce, text, aad));
        });
    }

    #[bench]
    fn bench_mrae_open_4096(b: &mut Bencher) {
        let mut rng = TheRng::new().unwrap();

        // Set up the key.
        let mut key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut key);
        let d2 = DeoxysII::new(&key).unwrap();

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill_bytes(&mut text);
        let mut aad = [0u8; 64];
        rng.fill_bytes(&mut aad);

        // Seal the payload.
        let sealed = d2.seal(&nonce, text.to_vec(), aad.to_vec());
        let ciphertext = sealed.unwrap();

        // Benchmark opening.
        b.iter(|| {
            let ct = ciphertext.to_vec();
            let aad = aad.to_vec();
            let _opened = black_box(d2.open(&nonce, ct, aad));
        });
    }

    #[bench]
    fn bench_mrae_box_seal_4096(b: &mut Bencher) {
        let mut rng = TheRng::new().unwrap();

        // Set up the keys.
        let (_a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, _b_priv) = generate_key_pair(); // Bob

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill_bytes(&mut text);
        let mut aad = [0u8; 64];
        rng.fill_bytes(&mut aad);

        // Benchmark box sealing.
        b.iter(|| {
            let _sealed = black_box(box_seal(
                &nonce,
                text.to_vec(),
                aad.to_vec(),
                &b_pub,
                &a_priv,
            ));
        });
    }

    #[bench]
    fn bench_mrae_box_open_4096(b: &mut Bencher) {
        let mut rng = TheRng::new().unwrap();

        // Set up the keys.
        let (a_pub, a_priv) = generate_key_pair(); // Alice
        let (b_pub, b_priv) = generate_key_pair(); // Bob

        // Set up the payload.
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        let mut text = [0u8; 4096];
        rng.fill_bytes(&mut text);
        let mut aad = [0u8; 64];
        rng.fill_bytes(&mut aad);

        // Seal the payload.
        let sealed = box_seal(&nonce, text.to_vec(), aad.to_vec(), &b_pub, &a_priv);
        let ciphertext = sealed.unwrap();

        // Benchmark box opening.
        b.iter(|| {
            let _opened = black_box(box_open(
                &nonce,
                ciphertext.clone(),
                aad.to_vec(),
                &a_pub,
                &b_priv,
            ));
        });
    }

    #[bench]
    fn bench_mrae_new(b: &mut Bencher) {
        let mut rng = TheRng::new().unwrap();

        // Set up the key.
        let mut key = [0u8; KEY_SIZE];
        rng.fill_bytes(&mut key);

        b.iter(|| {
            let _d2 = black_box(DeoxysII::new(&key).unwrap());
        });
    }
}
