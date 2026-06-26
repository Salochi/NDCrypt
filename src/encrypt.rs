use rand::RngCore;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::gka::{sample_small, ring_multiply, ring_add, encode_seed, RingElement};
use crate::keygen::PublicKey;

pub struct Ciphertext {
    pub c1: RingElement,
    pub c2: RingElement,
}

pub struct EncapsulationResult {
    pub ciphertext:  Ciphertext,
    pub shared_seed: Zeroizing<[u8; 32]>,
}

// Hashes the public key into a fixed-size digest used for FO binding.
pub fn hash_public_key(pk: &PublicKey) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([0x10]);
    for c in pk.a.coeffs.iter() { hasher.update(c.to_le_bytes()); }
    for c in pk.b.coeffs.iter() { hasher.update(c.to_le_bytes()); }
    let d = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// Hashes a ciphertext into a fixed-size digest used for FO re-encryption check.
pub fn hash_ciphertext(ct: &Ciphertext) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update([0x11]);
    for c in ct.c1.coeffs.iter() { hasher.update(c.to_le_bytes()); }
    for c in ct.c2.coeffs.iter() { hasher.update(c.to_le_bytes()); }
    let d = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

// Deterministic re-encapsulation used by the FO transform.
// Given seed and the pk_hash, derives the same ephemeral randomness and
// rebuilds (c1, c2) deterministically.  Used by decapsulate to re-encrypt
// the recovered seed and check it matches the received ciphertext.
pub fn encapsulate_deterministic(pk: &PublicKey, seed: &[u8; 32], pk_hash: &[u8; 32]) -> Ciphertext {
    // Derive a 32-byte PRNG seed from seed || pk_hash
    let mut hasher = Sha3_256::new();
    hasher.update([0x12]);
    hasher.update(seed);
    hasher.update(pk_hash);
    let prng_seed_digest = hasher.finalize();

    let mut prng_seed = [0u8; 32];
    prng_seed.copy_from_slice(&prng_seed_digest);

    // Use a deterministic PRNG seeded from above to sample s', e', e''
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    let mut rng = StdRng::from_seed(prng_seed);

    let encoded_seed_poly = encode_seed(seed);

    let s_prime       = sample_small(&mut rng);
    let e_prime       = sample_small(&mut rng);
    let e_prime_prime = sample_small(&mut rng);

    let as_prime = ring_multiply(&pk.a, &s_prime);
    let c1       = ring_add(&as_prime, &e_prime);

    let bs_prime = ring_multiply(&pk.b, &s_prime);
    let noisy_c2 = ring_add(&bs_prime, &e_prime_prime);
    let c2       = ring_add(&noisy_c2, &encoded_seed_poly);

    Ciphertext { c1, c2 }
}

// FO-transformed encapsulation:
//   1. Sample a random 32-byte seed m.
//   2. Derive ephemeral randomness r = H(0x12 || m || pk_hash) — same as
//      encapsulate_deterministic — so decapsulate can reproduce it exactly.
//   3. Build (c1, c2) using that deterministic r.
//   4. Return seed m and the ciphertext.
//
// Because r is fully determined by (m, pk), a forged ciphertext with arbitrary
// c1/c2 will almost certainly decrypt to some m' for which re-encrypt(m', pk)
// produces a different (c1', c2') — the decapsulator detects the mismatch
// and aborts instead of accepting the attacker-controlled seed.
pub fn encapsulate_payload(pk: &PublicKey, rng: &mut impl RngCore) -> EncapsulationResult {
    // Step 1 — random seed
    let mut shared_seed = [0u8; 32];
    rng.fill_bytes(&mut shared_seed);

    // Step 2/3 — deterministic ciphertext from (seed, pk)
    let pk_hash = hash_public_key(pk);
    let ciphertext = encapsulate_deterministic(pk, &shared_seed, &pk_hash);

    EncapsulationResult {
        ciphertext,
        shared_seed: Zeroizing::new(shared_seed),
    }
}
