use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha3::{Digest, Sha3_256};

use crate::gka::{RingElement, derive_signal_indices};
use crate::params::{N, Q, SIGNAL_COUNT};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum NdCryptError {
    // encrypt(): caller tried to encrypt more bytes than one point can hold.
    // Max is SIGNAL_COUNT - 1 = 31 bytes (one slot is reserved for the length byte).
    MessageTooLong,
    // decrypt(): the length byte recovered from S[0] is out of range.
    // This means the point was corrupted, tampered with, or the wrong seed/nonce was used.
    CorruptedLength,
    // decrypt_authenticated(): the MAC tag does not match.
    // The ciphertext was modified after encryption, or the wrong key was used.
    // Plaintext is NOT returned — the caller learns only that authentication failed.
    AuthenticationFailed,
    // decrypt_authenticated(): input slice is not exactly 1040 u16s
    // (1024 ciphertext coefficients + 16 tag words).
    BadCiphertextLength,
}

// ── Internal helpers ──────────────────────────────────────────────────────────

// Derives a 32-byte MAC key from the shared seed.
//
// Domain tag 0x04 keeps this key independent of every other SHA3 derivation
// in the system (signal indices use 0x01, keystream 0x02, background 0x03,
// nonce bases 0x05, confirmation 0x06).
//
// mac_key = SHA3-256(0x04 || seed)
fn derive_mac_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update([0x04]);
    h.update(seed);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// Computes the MAC tag over a ciphertext point for a given nonce.
//
// SHA3-256 is not vulnerable to length-extension attacks (unlike SHA2), so
// the simple keyed-prefix construction is secure:
//
//   tag = SHA3-256(mac_key || nonce_le8 || coeff[0]_le2 || ... || coeff[1023]_le2)
//
// The nonce is included so a tag computed for one point cannot be transplanted
// onto a different point at the same position in a different session.
// The mac_key binds the tag to the shared seed so only the two parties can verify it.
fn compute_mac_with_aad(mac_key: &[u8; 32], nonce: u64, aad: &[u8], ct: &RingElement) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(mac_key);
    h.update(nonce.to_le_bytes());
    h.update((aad.len() as u64).to_le_bytes());
    h.update(aad);
    for coeff in ct.coeffs.iter() {
        h.update(coeff.to_le_bytes());
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// Derives a PRNG seeded for background coordinate generation.
//
// A single SHA3 call produces a 32-byte seed for StdRng (ChaCha12).
// The PRNG then fills all 1024 background slots via rejection sampling,
// replacing the old approach of calling SHA3-256 once per coordinate (1024 calls).
//
// Domain 0x03 matches the tag used in the previous per-coordinate design,
// keeping the derivation distinct from signal indices and keystream.
fn background_rng(seed: &[u8; 32], nonce: u64) -> StdRng {
    let mut h = Sha3_256::new();
    h.update([0x03]);
    h.update(nonce.to_le_bytes());
    h.update(seed);
    let digest = h.finalize();
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&digest);
    StdRng::from_seed(rng_seed)
}

// Samples one uniform value in Z_Q from the PRNG via rejection sampling.
//
// Masking to 14 bits (0x3FFF = 0..16383) and rejecting values >= Q gives
// a perfectly uniform distribution over Z_Q = {0..12288}.
// Expected iterations: 16384/12289 ≈ 1.33 — no meaningful performance cost.
fn sample_zq(rng: &mut StdRng) -> u16 {
    loop {
        let candidate = rng.next_u32() & 0x3FFF;
        if candidate < Q as u32 {
            return candidate as u16;
        }
    }
}

// Derives the keystream used to mask signal coordinate values.
//
// Produces `count` uniform Z_Q values from a StdRng (ChaCha12) seeded by
// SHA3-256(0x02 || nonce || seed). One value is consumed per signal slot:
// the length byte and each message byte each get their own Z_Q mask.
//
// Using Z_Q values (not bytes) for masking means both background and signal
// coordinates are uniform over Z_Q — an attacker cannot distinguish them
// by range. The old approach produced 0..255 for both, which was correct for
// indistinguishability but wasted 6 bits of the field per coordinate.
fn derive_keystream_zq(seed: &[u8; 32], nonce: u64, count: usize) -> Vec<u16> {
    let mut h = Sha3_256::new();
    h.update([0x02]);
    h.update(nonce.to_le_bytes());
    h.update(seed);
    let digest = h.finalize();
    let mut rng_seed = [0u8; 32];
    rng_seed.copy_from_slice(&digest);
    let mut rng = StdRng::from_seed(rng_seed);

    (0..count).map(|_| sample_zq(&mut rng)).collect()
}

// ── Core encrypt / decrypt ────────────────────────────────────────────────────
//
// These two functions are intentionally pub(crate): they perform no authentication
// and must never be called directly from outside this crate.  All external callers
// (including the WASM bindings in lib.rs) must use encrypt_authenticated /
// decrypt_authenticated, which append and verify a MAC tag before any plaintext
// is returned.
//
// Bug #3 context: the previous WASM API called these functions directly, meaning
// an active attacker could flip signal coordinates and have the receiver silently
// decrypt attacker-controlled bytes.  Restricting visibility to pub(crate) ensures
// that path is closed at the type-system level — no accidental regression possible.

// Encrypts a message into a 1024-dimensional point over Z_Q.
//
// Signal coordinates carry the payload; all other coordinates are indistinguishable
// background noise.  Both background and signal values are uniform in Z_Q so no
// statistical test can identify which coordinates are signal.
//
// Layout inside the point:
//   S[0]       — encrypted length byte  (allows self-framing; no out-of-band length needed)
//   S[1..=len] — encrypted message bytes
//   all others — uniform Z_Q background noise
//
// Encoding: signal_coord = (mask_i + value) % Q   where mask_i is a Z_Q keystream word.
// Decoding: value = (signal_coord + Q - mask_i) % Q.
//
// Maximum message: SIGNAL_COUNT - 1 = 31 bytes per point.
// For longer messages the caller increments the nonce and sends another point.
pub(crate) fn encrypt(
    message: &[u8],
    seed: &[u8; 32],
    nonce: u64,
) -> Result<RingElement, NdCryptError> {
    if message.len() >= SIGNAL_COUNT {
        return Err(NdCryptError::MessageTooLong);
    }

    let signal_indices = derive_signal_indices(seed, nonce);
    // One Z_Q mask per slot: index 0 masks the length, indices 1..=len mask the message.
    let keystream = derive_keystream_zq(seed, nonce, message.len() + 1);

    // Fill all 1024 coordinates with uniform Z_Q background.
    // StdRng (ChaCha12) replaces the old 1024-SHA3-call loop — one PRNG seed
    // derivation instead of one full hash per coordinate.
    let mut bg_rng = background_rng(seed, nonce);
    let mut point = RingElement { coeffs: [0u16; N] };
    for coord in point.coeffs.iter_mut() {
        *coord = sample_zq(&mut bg_rng);
    }

    // Overwrite signal positions with encrypted payload.
    // Additive Z_Q masking: enc = (mask + plaintext) % Q.
    // The mask is drawn from the same Z_Q distribution as the background,
    // so the resulting signal coordinate is also uniform in Z_Q.
    let enc_len = (message.len() as u16 + keystream[0]) % Q as u16;
    point.coeffs[signal_indices[0] as usize] = enc_len;

    for i in 0..message.len() {
        let enc_byte = (message[i] as u16 + keystream[i + 1]) % Q as u16;
        point.coeffs[signal_indices[i + 1] as usize] = enc_byte;
    }

    Ok(point)
}

// Decrypts a 1024-dimensional point back into the original message bytes.
//
// Reconstructs signal indices and keystream from (seed, nonce), then extracts
// and unmasks each signal coordinate in reverse.
// Decoding: value = (signal_coord + Q - mask) % Q, then take low 8 bits for bytes.
pub(crate) fn decrypt(
    point: &RingElement,
    seed: &[u8; 32],
    nonce: u64,
) -> Result<Vec<u8>, NdCryptError> {
    let signal_indices = derive_signal_indices(seed, nonce);
    // Recover the length first using only the first keystream word.
    let len_keystream = derive_keystream_zq(seed, nonce, 1);
    let enc_len = point.coeffs[signal_indices[0] as usize];
    let message_len = ((enc_len + Q - len_keystream[0]) % Q) as usize;

    if message_len >= SIGNAL_COUNT {
        return Err(NdCryptError::CorruptedLength);
    }

    // Now that we know the length, derive the remaining keystream words.
    let keystream = derive_keystream_zq(seed, nonce, message_len + 1);

    let mut message = Vec::with_capacity(message_len);
    for i in 0..message_len {
        let enc_byte = point.coeffs[signal_indices[i + 1] as usize];
        // Unmask and take the low byte — message bytes are always 0..255.
        let plain = ((enc_byte + Q - keystream[i + 1]) % Q) as u8;
        message.push(plain);
    }

    Ok(message)
}

// ── Authenticated encrypt / decrypt ──────────────────────────────────────────

// Encrypts `payload` and appends a 32-byte MAC tag, returning 1040 u16s.
//
// Output layout:
//   [0..1024)    — ciphertext point (1024 u16 coefficients)
//   [1024..1040) — MAC tag (32 bytes packed as 16 u16s, little-endian)
//
// The MAC is computed AFTER encryption over (mac_key || nonce || ciphertext coefficients).
// Including the nonce in the MAC input ensures a tag from one message cannot be
// replayed for a different nonce, even with an identical plaintext.
//
// Bug #3 fix: without this tag, an attacker could flip arbitrary signal coordinates
// and the receiver would silently decrypt garbage or attacker-controlled bytes.
// Now any single-bit modification to the ciphertext causes MAC verification to fail
// and the plaintext is never returned.
pub fn encrypt_authenticated(
    payload: &[u8],
    seed: &[u8; 32],
    nonce: u64,
) -> Result<Vec<u16>, NdCryptError> {
    encrypt_authenticated_with_aad(payload, seed, nonce, &[])
}

pub fn encrypt_authenticated_with_aad(
    payload: &[u8],
    seed: &[u8; 32],
    nonce: u64,
    aad: &[u8],
) -> Result<Vec<u16>, NdCryptError> {
    let ct = encrypt(payload, seed, nonce)?;

    let mac_key = derive_mac_key(seed);
    let tag = compute_mac_with_aad(&mac_key, nonce, aad, &ct);

    // Pack the 1024-coefficient ciphertext followed by the 16-word MAC tag.
    let mut out = Vec::with_capacity(1040);
    out.extend_from_slice(&ct.coeffs);
    // Pack 32 tag bytes as 16 u16 words (2 bytes each, little-endian).
    for chunk in tag.chunks_exact(2) {
        out.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    Ok(out)
}

// Verifies the MAC tag then decrypts, returning the plaintext only on success.
//
// Input must be exactly 1040 u16s (1024 ciphertext + 16 tag words).
// The MAC is verified BEFORE any decryption work is done, and the result of
// verification is checked with a constant-time byte fold to avoid timing oracles.
// Plaintext is returned only if the fold is zero — i.e. every tag byte matched.
//
// Bug #3 fix: callers receive either the correct plaintext or AuthenticationFailed.
// There is no path that returns plaintext from a modified ciphertext.
pub fn decrypt_authenticated(
    cipher: &[u16],
    seed: &[u8; 32],
    nonce: u64,
) -> Result<Vec<u8>, NdCryptError> {
    decrypt_authenticated_with_aad(cipher, seed, nonce, &[])
}

pub fn decrypt_authenticated_with_aad(
    cipher: &[u16],
    seed: &[u8; 32],
    nonce: u64,
    aad: &[u8],
) -> Result<Vec<u8>, NdCryptError> {
    if cipher.len() != 1040 {
        return Err(NdCryptError::BadCiphertextLength);
    }

    // Split into ciphertext coefficients and tag words.
    let ct_coeffs = &cipher[..1024];
    let tag_words = &cipher[1024..];

    // Reconstruct the RingElement for MAC verification.
    let mut coeffs = [0u16; N];
    coeffs.copy_from_slice(ct_coeffs);
    let ct = RingElement { coeffs };

    // Unpack the received tag from 16 u16 words back to 32 bytes.
    let mut received_tag = [0u8; 32];
    for (i, &word) in tag_words.iter().enumerate() {
        let bytes = word.to_le_bytes();
        received_tag[2 * i] = bytes[0];
        received_tag[2 * i + 1] = bytes[1];
    }

    // Compute the expected tag independently.
    let mac_key = derive_mac_key(seed);
    let expected_tag = compute_mac_with_aad(&mac_key, nonce, aad, &ct);

    // Constant-time comparison: fold XOR across all 32 bytes.
    // Any nonzero result means at least one byte differed — reject entirely.
    // Using a fold (not early return) ensures the comparison time is the same
    // whether the tags differ in the first byte or the last.
    let mut diff: u8 = 0;
    for (a, b) in expected_tag.iter().zip(received_tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(NdCryptError::AuthenticationFailed);
    }

    // MAC passed — now safe to decrypt.
    decrypt(&ct, seed, nonce)
}

// ── Session wrapper ───────────────────────────────────────────────────────────

// Owns the shared seed and enforces strictly increasing nonces.
//
// encrypt() and decrypt() take &mut self so the nonce counter advances with
// every call, making (seed, nonce) reuse structurally impossible within a session.
//
// Bug #5 fix: if the same (seed, nonce) were used for two messages, the keystream
// would be identical and XOR of the two ciphertexts would equal XOR of the two
// plaintexts — a complete break.  The session struct prevents this by ensuring the
// nonce strictly increases.  The +2 step preserves the even/odd parity split
// established by get_nonce_base(party_index): Alice always holds even nonces, Bob
// always holds odd ones (or vice-versa), so their streams can never collide even
// if both counters start from the same low value.
pub struct NdCryptSession {
    seed: [u8; 32],
    nonce: u64,
}

impl NdCryptSession {
    pub fn new(seed: [u8; 32], nonce_base: u64) -> Self {
        NdCryptSession {
            seed,
            nonce: nonce_base,
        }
    }

    pub fn encrypt(&mut self, message: &[u8]) -> Result<Vec<u16>, NdCryptError> {
        let nonce = self.nonce;
        // Advance the counter BEFORE the call so the nonce cannot be reused even
        // if the caller ignores a returned error and calls encrypt again.
        self.nonce += 2;
        encrypt_authenticated(message, &self.seed, nonce)
    }

    pub fn decrypt(&mut self, cipher: &[u16]) -> Result<Vec<u8>, NdCryptError> {
        let nonce = self.nonce;
        self.nonce += 2;
        decrypt_authenticated(cipher, &self.seed, nonce)
    }
}

impl Drop for NdCryptSession {
    // Zeroize the seed on drop so it does not persist in memory after the session ends.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_metadata_must_match() {
        let seed = [0x42u8; 32];
        let nonce = 17;
        let payload = b"hello";
        let aad = b"data|1|0|1|5";
        let tampered_aad = b"data|1|1|1|5";

        let cipher = encrypt_authenticated_with_aad(payload, &seed, nonce, aad).unwrap();

        assert_eq!(
            decrypt_authenticated_with_aad(&cipher, &seed, nonce, aad).unwrap(),
            payload
        );
        assert!(matches!(
            decrypt_authenticated_with_aad(&cipher, &seed, nonce, tampered_aad),
            Err(NdCryptError::AuthenticationFailed)
        ));
    }

    #[test]
    fn empty_plaintext_is_distinct_from_authentication_failure() {
        let seed = [0x24u8; 32];
        let nonce = 23;
        let aad = b"meta|2|0|1|0";
        let cipher = encrypt_authenticated_with_aad(&[], &seed, nonce, aad).unwrap();

        assert_eq!(
            decrypt_authenticated_with_aad(&cipher, &seed, nonce, aad).unwrap(),
            Vec::<u8>::new()
        );
        assert!(matches!(
            decrypt_authenticated_with_aad(&cipher, &seed, nonce, b"meta|2|0|1|1"),
            Err(NdCryptError::AuthenticationFailed)
        ));
    }

    #[test]
    fn poc_legacy_mac_allows_metadata_relabel_attack() {
        let seed = [0x7au8; 32];
        let nonce = 44;
        let payload = b"pay bob";

        let honest_metadata = br#"{"kind":"data","transferId":10,"chunkIndex":0,"totalChunks":1,"totalBytes":7}"#;
        let attacker_metadata = br#"{"kind":"data","transferId":99,"chunkIndex":3,"totalChunks":4,"totalBytes":7}"#;

        // Legacy behavior: the tag covers only nonce + ciphertext, not the
        // plaintext envelope. A relay can move this valid chunk into a different
        // transfer/chunk slot and decryption still succeeds.
        let legacy_cipher = encrypt_authenticated(payload, &seed, nonce).unwrap();
        let legacy_plaintext = decrypt_authenticated(&legacy_cipher, &seed, nonce).unwrap();
        assert_eq!(legacy_plaintext, payload);
        println!(
            "POC vulnerable path: ciphertext for {:?} was accepted after relabeling to {:?}",
            String::from_utf8_lossy(honest_metadata),
            String::from_utf8_lossy(attacker_metadata),
        );

        // Patched behavior: the same metadata is AAD. Relabeling changes the MAC
        // input and is rejected before plaintext is returned.
        let patched_cipher =
            encrypt_authenticated_with_aad(payload, &seed, nonce, honest_metadata).unwrap();
        assert!(matches!(
            decrypt_authenticated_with_aad(&patched_cipher, &seed, nonce, attacker_metadata),
            Err(NdCryptError::AuthenticationFailed)
        ));
        assert_eq!(
            decrypt_authenticated_with_aad(&patched_cipher, &seed, nonce, honest_metadata).unwrap(),
            payload
        );
        println!("POC patched path: relabeled metadata was rejected by the AAD MAC");
    }
}
